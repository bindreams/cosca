//! The console-event proxy as an executable: `cosca::init()` plays the proxy when the arguments say
//! so. Started any other way it says so and exits with the proxy's usage answer.

fn main() {
    cosca::ctrl_proxy_main()
}
