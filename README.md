# IDQL-specs
This is the repository for development of IDQL Policy Language. IDQL's objective is to standardize access policy across the cloud and the stack usable in standalone deployments all the way to hybrid multi-cloud scenarios.

## Why Is IDQL Needed?
Why does the world need another standard?
* Multi-cloud access policy does not exist.
* Incumbent vendors are not motivated to address multi-cloud challenges.
* Distributed architectures require policy consistency across disparate platforms, domains and technologies.
* Without a standard there will be inconsistency, risk through silos, greater cost and lock-in.

How does IDQL compare to other standards?
* OPA (Open Policy Agent (CNCF) – Focused on K8S cluster management, networking, and microservices - not end user identity.
* SPIFFE/Spire (CNCF) – focused on App to App identity using x509, not end user identity.
* SAML, OIDC, OAuth are all protocols for SSO and Authorization but not end user identity policy.
* XACML (OASIS) – focused on fine grained entitlements not end user identity policy. Not declarative, requires custom code and is too complex.
