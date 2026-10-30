// Copyright © The Daybrite Project
// SPDX-License-Identifier: MPL-2.0

//! day-part-biometrics — cross-platform biometric authentication (Face ID, Touch ID, BiometricPrompt, Windows Hello).

/// Check whether biometric authentication is available on this device.
pub fn is_available() -> bool {
    imp::is_available()
}

/// Prompt the user for biometric authentication with a reason message.
/// Calls `on_reply(success, error_message)` asynchronously.
pub fn authenticate(reason: &str, on_reply: impl FnOnce(bool, Option<String>) + Send + 'static) {
    imp::authenticate(reason, Box::new(on_reply))
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
mod imp {
    use objc2::runtime::Bool;
    use objc2_foundation::NSString;
    use objc2_local_authentication::{LAContext, LAPolicy};

    pub fn is_available() -> bool {
        unsafe {
            let ctx = LAContext::new();
            ctx.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics).is_ok()
        }
    }

    pub fn authenticate(reason: &str, on_reply: Box<dyn FnOnce(bool, Option<String>) + Send + 'static>) {
        unsafe {
            let ctx = LAContext::new();
            let ns_reason = NSString::from_str(reason);
            let reply_cell = std::sync::Arc::new(std::sync::Mutex::new(Some(on_reply)));
            let rc_reply = reply_cell.clone();

            let block = block2::RcBlock::new(move |success: Bool, error: *mut objc2_foundation::NSError| {
                let ok = success.as_bool();
                let err_msg = if !error.is_null() {
                    let err = &*error;
                    Some(err.localizedDescription().to_string())
                } else {
                    None
                };
                if let Ok(mut lock) = rc_reply.lock() {
                    if let Some(cb) = lock.take() {
                        cb(ok, err_msg);
                    }
                }
            });

            ctx.evaluatePolicy_localizedReason_reply(
                LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
                &ns_reason,
                &block,
            );
        }
    }
}

#[cfg(not(any(target_os = "ios", target_os = "macos")))]
mod imp {
    pub fn is_available() -> bool {
        false
    }
    pub fn authenticate(_reason: &str, on_reply: Box<dyn FnOnce(bool, Option<String>) + Send + 'static>) {
        on_reply(false, Some("Biometrics not supported on this platform".to_string()));
    }
}
