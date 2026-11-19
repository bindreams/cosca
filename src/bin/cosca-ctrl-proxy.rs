//! The console-event proxy as an executable: `cosca::init_helpers()` plays the proxy when
//! the environment says so (`__COSCA_HELPER=ctrl-proxy`). With the variable unset it says so and exits with
//! the proxy's usage answer; an unknown role exits with the unknown-role code, as `init_helpers` documents.

fn main() {
    cosca::ctrl_proxy_main()
}
