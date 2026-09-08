# Public FreeTSA certificates for offline regression tests

Retrieved from the public provider endpoints on 2026-09-08:

- `freetsa-root.pem`: https://www.freetsa.org/files/cacert.pem
- `freetsa-tsa.pem`: https://www.freetsa.org/files/tsa.crt

Certificate SHA-256 fingerprints (DER):

- Root: A6379E7CECC05FAA3CBF076013D745E327BBBAA38C0B9AF22469D4701D18AABC
- TSA: 32E841A95CC1164101FFDE41298EF2FC75C1C4372EF095E88A6BBD47DFB191FC

The root expires 2041-03-07; the TSA certificate expires 2040-02-02.
Tests configure these explicitly, outside the copied evidence bundles. The CLI
never silently loads these test roots. No private keys are stored here. Operators
must authenticate and provision their own trust configuration independently.
