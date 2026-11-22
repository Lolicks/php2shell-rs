# Acceptable Use — PHP2Shell-RS

This project is a **diagnostic and laboratory tool**. It does not contain
exploitation code and must not be used to attack systems.

## Permitted

- fingerprinting systems you own or have explicit written permission to test;
- importing, validating and inspecting build profiles;
- running the local loopback mock laboratory;
- managing your own Docker Compose laboratory in `mode = "lab"`;
- defensive research, detection engineering and patch verification.

## Not permitted

- using the tool against third-party infrastructure;
- attempting to obtain shells, execute commands or bypass access controls;
- sending OOM/DoS workloads or saturating workers;
- building target lists or mass-scanning networks;
- redistributing the archived Python exploit research as an attack toolkit.

`legacy/python/` contains the original research sources for audit purposes
only. They are not built, tested, installed or invoked by PHP2Shell-RS.

The license grants copyright permissions only; it never grants authorization
to test any system.
