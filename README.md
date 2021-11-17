# IDQL-specs
This is the repository for development of IDQL Policy Language. 

## Introduction

IDQL's objective is to standardize access policy and associated APIs across the cloud and the stack usable in 
standalone deployments all the way to hybrid multi-cloud scenarios.

IDQL specifications can be found [here](specs/Specifications.md).

### Why Is IDQL Needed?
IDQL's goal is to produce a unified policy system because:
* Multi-cloud access policy does not exist.
* Incumbent vendors are not motivated to address multi-cloud challenges.
* Distributed architectures require policy consistency across disparate platforms, domains and technologies.
* Without a standard there will be inconsistency, risk through silos, greater cost and lock-in.

![](./collateral/images/IDQL-3d.png "IDQL 3D")

### How does IDQL compare to other standards?
* CNCF [Open Policy Agent](https://www.openpolicyagent.org) (OPA) – Focused on K8S cluster management, networking, and 
  microservices. It is expected that IDQL will be supported in OPA by using a set of (tentatively
  planned OPA Rego modules that will be able to interpret IDQL policy directly in OPA Agents.
* CNCF [SPIFFE/Spire](https://spiffe.io) – focused on App to App identity using x509, not end user identity.
* [SAML](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=security), [OIDC](https://openid.net),[ OAuth](https://tools.ietf.org/wg/oauth/) are all protocols for SSO and Authorization but not end user identity policy.
* [XACML](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=xacml) (OASIS) – focused on fine-grained 
  entitlements not end user identity policy. Not declarative, requires custom code and is too complex.

### What are the basics?

IDQL Policy is a series of meta statements that define simple policy rules that are then translated and deployed to 
the correct cloud providers, layers and components. A basic statement consists of a `Subject` + `Action` + target 
`Object` + `condition`.

![](./collateral/images/IDQL-statement.png "IDQL Statement")

IDQL policy is defined in either JSON or YAML human-readable files. IDQL is intended to support both lowest common 
denominator User App Policies (? source) and extended features such as contextual access. IDQL policy is then 
translated into proprietary policy and published into existing IAM systems through APIs and gateways. 

## The Standard Process

We are working with developers and customers to build a set of specifications and open source as part of the Cloud 
Native Computing Foundation. The IDQL Working Group will be responsible for the policy specification and API 
definitions published on this site. 

## How to Contribute

TBD.