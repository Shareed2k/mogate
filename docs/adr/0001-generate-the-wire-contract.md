# Generate the Wire Contract from one schema

The Injection Session Wire Contract is defined once in a checked-in JSON schema
and generates both the Go representation and the C header. Generated outputs
are committed and checked for drift, so normal builds require no generator and
the C-only injector never embeds a Go runtime. Existing protocol-v1 values and
layouts remain unchanged; new operations are additive and unsupported
operations fail explicitly instead of silently becoming local operations.
