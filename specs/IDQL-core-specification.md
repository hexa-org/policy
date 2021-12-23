# IDQL Core Specification

This specification defines the IDQL policy language. IDQL is designed to be a general purpose, platform-neutral 
policy language for use in hybrid and multi-cloud environments. IDQL is intended support:
* Centralized management and control of cloud based applications
* A platform-neutral specification that can be mapped into proprietary policy systems or be interpreted directly
* Existing standard schemas where possible.

## Conventions and Terminology

All IDQL specification use a common formatting convention and terminology. For information see [Conventions](Conventions.md).

## Copyright Notice

Copyright (C) 2021, Strata Identity Inc. All rights reserved.

This document is available for use under the APL 2.0 [Apache License](../LICENSE).

Table of Contents
=================

  * [1.0 Introduction](#10-introduction)
  * [2.0 YAML and JSON Schema and Media Types](#20-yaml-and-json-schema-and-media-types)
  * [3.0 Policy Environment](#30-policy-environment)
    * [3.1 Project Context](#31-project-context)
    * [3.2 How Policy Is Deployed](#32-how-policy-is-deployed)
    * [3.3 Contextual Attributes](#33-contextual-attributes)
  * [4.0 IDQL Policy Statements](#40-idql-policy-statements)
    * [4.1 Id Attribute](#41-id-attribute)
    * [4.2 Meta Information](#42-meta-information)
    * [4.3 Subject](#43-subject)
      * [4.3.1 JWT Sub-type](#431-jwt-sub-type)
    * [4.4 Actions](#44-actions)
      * [4.4.1 IETF Domain URNs](#441-ietf-domain-urns)
      * [4.4.2 Amazon ARN Actions](#442-amazon-arn-actions)
      * [4.4.3 Microsoft Azure URNs for Actions](#443-microsoft-azure-urns-for-actions)
      * [4.4.4 Google URNs for Actions](#444-google-urns-for-actions)
    * [4.5 Object](#45-object)
    * [4.6 Scopes](#46-scopes)
    * [4.7 Condition](#47-condition)
  * [5.0 Appendix A - Use Cases](#50-appendix-a---use-cases)
    * [5.1 General RBAC Policy Examples](#51-general-rbac-policy-examples)
      * [5.1.1 Google Policy](#511-google-policy)
      * [5.1.2 AWS API Policy](#512-aws-api-policy)
      * [5.1.3 Azure App Role](#513-azure-app-role)


---
## 1.0 Introduction
IDQL or Identity Query Language is a declarative policy language that can be expressed in either
[YAML](https://yaml.org/spec/) 
or [JSON (RFC8259)](https://datatracker.ietf.org/doc/html/rfc8259). IDQL is intended to be used to manage security 
policy in distributed, hybrid [definition?], multi-cloud environments. The intent of IDQL is that all components, of a 
cloud based application from network to application layers may manage access regardless of proprietary platform or 
container. As a declarative policy system IDQL policy may be enforced directly or mapped and converted into 
proprietary platforms that implement IDQL enabled gateways (see: open source project TBD).

![](../collateral/images/IDQL-rule.png "IDQL-rule")

An IDQL policy rule identifies a `subject` provider that is permitted one or more `actions` against a target `object` 
with an OPTIONAL set of `scopes` that MAY be used in a condition or returned to the target (e.g. dataSet = "US"). 
IDQL policy MAY be expressed in YAML or JSON format.

IDQL is intended to be used with an [IDQL Policy Gateway API] (the "Gateway") which enables retrieval of deployment 
environments and the ability to retrieve, update, and provision policy. The Gateway defines identifiers for the 
assets referred to in 
IDQL policy such as: 
* `provId` - The identifier of an Identity Provider (e.g. "myGoogleIDP") that will provide the "subjects" referred to in 
  the policy.
* `assetId` - The identifier of a service or entity where policy is deployed (e.g. "CanaryProfileService").

### Example IDQL Policy

The following shows a policy that users from a provider known as "myGoogleIDP" or entities with an IP address 
matching IP CIDR 192.168.0.1/24 may perform a `createProfile` or `editProfile` action against the target object 
`CanaryProfileService`. When from "myGoogleIDP" The`editProfile` action also 
requires that the User `employeeType` be equal to `contract`. 

The YAML representation of an example IDQL policy:
```yaml
---
idql-policies:
  - id: CanaryProfileGoogleUpdate
    meta:
      vers: '0.1'
      date: 2021-08-01 21:32:44 UTC
      disp: Access enabling user self service for users with role
      app: CanaryBank1
      layer: Browser
    subject:
      subType: op
      provId: myGoogleIDP
      role: canarySelfService
    actions:
      - name: createProfile
        actionUri: accountCreate
      - name: editProfile
        actionUri: accountEdit
    object:
      assetId: CanaryProfileService
      pathSpec: "/Profile/*"
  - id: EditProfileGoogleUpdate AdminContractor
    meta:
      vers: '0.1'
      date: 2021-08-01 21:32:44 UTC
      disp: Access policy enabling contract staff to edit profiles
      app: CanaryBank1
      layer: Browser
    subject:
      subType: op
      provId: myGoogleIDP
    actions:
      - name: editProfile
        actionUri: accountEdit
    object:
      assetId: CanaryProfileService
      pathSpec: "/Profile/*"
    condition:
      rule: User:employeeType eq contract
      action: allow
  - id: CanaryProfileInternalNetUpdate
    meta:
      vers: '0.1'
      date: 2021-08-01 21:32:44 UTC
      disp: Enabling profile update for internal network services
      app: CanaryBank1
      layer: Services
    subject:
      subType: net
      cidr: 192.168.1.0/24
      members:
       - WorkFlowSvcAcnt
    actions:
      - name: createProfile
        actionUri: accountCreate
      - name: editProfile
        actionUri: accountEdit
    object:
      assetId: CanaryProfileService
      pathSpec: "/Profile/*"
```

In the above example, 3 policies are defined:
* The first policy allows users authenticated via a Google IDP with role "canarySelfService" to invoke the actions 
  "createProfile" and "editProfile" on the "CanaryProfileService" asset. In this case, the role would likely be 
  asserted in a JWT assertion.
* In the second policy, contract employees of CanaryBank identified by the condition `User:employeeType eq contract` 
  are permitted to invoke the editProfile action of the "CanaryProfileService". The condition implies the policy 
  decision point is able to access local SCIM, LDAP, or database containing User information.  
* The third policy enables internal services to perform actions and are authorized by IP subnet and a service 
  account "WorkFlowSvcAcnt".

The JSON representation of the YAML policy above:
```json lines
{
  "idql-policies": [
    {
      "id": "CanaryProfileGoogleUpdate",
      "meta": {
        "vers": "0.1",
        "date": "2021-08-01 21:32:44 UTC",
        "disp": "Access enabling user self service for users with role",
        "app": "CanaryBank1",
        "layer": "Browser"
      },
      "subject": {
        "subType": "op",
        "provId": "myGoogleIDP",
        "role": "canarySelfService"
      },
      "actions": [
        {
          "name": "createProfile",
          "actionUri": "accountCreate"
        },
        { "name": "editProfile",
          "actionUri": "accountEdit"
        }
      ],
      "object": {
        "assetId": "CanaryProfileService",
        "pathSpec": "/Profile/*"
      }
    },
    {
      "id": "EditProfileGoogleUpdate AdminContractor",
      "meta": {
        "vers": "0.1",
        "date": "2021-08-01 21:32:44 UTC",
        "disp": "Access policy enabling contract staff to edit profiles",
        "app": "CanaryBank1",
        "layer": "Browser"
      },
      "subject": {
        "subType": "op",
        "provId": "myGoogleIDP"
      },
      "actions": [
        {
          "name": "editProfile",
          "actionUri": "accountEdit"
        }
      ],
      "object": {
        "assetId": "CanaryProfileService",
        "pathSpec": "/Profile/*"
      },
      "condition": {
        "rule": "User:employeeType eq contract",
        "action": "allow"
      }
    },
    {
      "id": "CanaryProfileInternalNetUpdate",
      "meta": {
        "vers": "0.1",
        "date": "2021-08-01 21:32:44 UTC",
        "disp": "Enabling profile update for internal network services",
        "app": "CanaryBank1",
        "layer": "Services"
      },
      "subject": {
        "subType": "net",
        "cidr": "192.168.1.0/24",
        "members": ["WorkFlowSvcAcnt"]
      },
      "actions": [
        {
          "name": "createProfile",
          "actionUri": "accountCreate"
        },
        { "name": "editProfile",
          "actionUri": "accountEdit"
        }
      ],
      "object": {
        "assetId": "CanaryProfileService",
        "pathSpec": "/Profile/*"
      }
    }
  ]
}
```
----

## 2.0 YAML and JSON Schema and Media Types

IDQL MAY be expressed in either [YAML](https://yaml.org) or 
[JSON (RFC8259)](https://datatracker.ietf.org/doc/html/rfc8259) form. This specification uses the 
[JSON Schema Specification](https://json-schema.org) to formalize its [format](../schema/idql-policy.schema.json) for 
validation purposes.  

The media type for IDQL YAML is `application/idql+yaml` and `application/idql+json` for JSON formatted content. 

>TODO: write and submit IANA registrations for application/idql+json and application/idql+yaml.  Note: `text/yaml` 
though popular is not formally defined. `text` media type is intended for unstructured textual data.  See Sec 4.2.1 
and 4.2.5 of RFC6838.

---
## 3.0 Policy Environment

In order to define policy, IDQL assumes a pre-defined set of assets where policy will be deployed which are 
identified by an identifier. Similarly, IDQL assumes a set of 
Identity Providers that define the subjects against which policy decisions are made. In addition to project 
information, policy conditions MAY use contextual attributes to apply conditions against run time request information.

### 3.1 Project Context

IDQL assumes project configuration information (e.g. from the Policy Gateway) that defines the sources (subjects) and 
targets (objects) of 
data upon which IDQL 
rules operate. The Policy Gateway provides the following objects
* _Identity Providers_ define `authId` identifiers are used in a `subject` clause in IDQL. Each provider SHOULD 
  have a set of claims which may be used in policy conditions. Where possible, claims from Identity Providers
  should be mapped to definitions from: 
  * [OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.
    html#Claims). 
  * And, for extended User profile attributes, use 
    [SCIM User schema under IANA](https://www.iana.org/assignments/scim/scim.xhtml).
* _Assets_ are referred to in IDQL policy as part of the `object` attribute. An asset represents on object where 
  policy may be applied. An asset often has a pre-defied set of permissible `actions` (e.g. roles or permissions) that 
  MAY be allowed, denied, and/or scoped in within an IDQL policy rule. 

### 3.2 How Policy Is Deployed

In practice, a Policy Gateway system maps IDQL Policy to each platform and its native policy system.
In different cloud native environments, policy decision and enforcement may occur using different models. Policy 
deployment, processing and enforcement may be local to the asset (e.g. using the 
[Open Poilicy Agent sidecar pattern](https://www.openpolicyagent.org/docs/latest/integration/#comparison)), 
delivered through a shared service Policy Decision Point (PDP), or handled directly through a platform's administrative 
interfaces, or other method. As a declarative policy system, it is assumed that the policy administrative gateway 
services for IDQL will handle delivery and configuration with the defined policy assets.

#### 3.2.1 Typical Asset Descriptors
A typical asset has attributes such as project id, data center region and other items required by platform vendors 
(such as AWS, Azure, GCP, or other).  For example:

For AWS, the server information needed to identify an asset might include:
```json
{
  "id": "CanaryProfileService",
  "type": "aws",
  "account-id": "xyz",
  "api-id": "a1234567890",
  "region": "us-east-1",
  "stage-name": "",
  "http-verb": "",
  "resoource-path-specifier": "/Profile/*"
}
```

For Azure, configuration information includes:
```json
{
  "id": "CanaryProfileService",
  "type": "azure.waf",
  "subscription": "s1234567890",
  "resourceGroup": "xyz",
  "api-id": "8763f1c4-0000-0000-0000-158e9ef97d6a",
  "location": "us-east-1",
  "stage-name": "",
  "resoource": "/Profile/*"
}
```

For GCP, configruation information could include:
```json
{
  "id": "CanaryProfileService",
  "type": "GCP.compute",
  "projectid": "xyz",
  "region": "",
  "resourceid": "55ec91ba47ba4f44adf0ef3b748e430f"
}
```

In practice, a Policy Gateway will also need to be configured with an appropriate 
administrative credential (not shown) to make changes.

In the above example asset descriptors note that each JSON structure has a "type" attribute. A 
policy gateway and policy editor will use `type` to look up asset schema using [JSON Schema](https://json-schema.org) or [JSON-LD](https://json-ld.org).

> Question: Do we need both JSON-Schema and JSON-LD?  Both are self-describing, however JSON Schema does provide 
> attribute combination rules whereas JSON-LD simply describes simple objects and attributes.

### 3.3 Contextual Attributes

When a policy rule is tested, certain run-time contextual information is made available for IDQL `conditions`.

Request context attributes:
* `req` - Holds information about the incoming request context. E.g. `req.ip` or `req.protocol`.
  * `ip` - The IP address of the requestor.
  * `protocol` - The protocol portion of the request URI (e.g. HTTP).
  * `time` - The time of the client request
  * `param.<name>` - Returns the value of any request parameter in the URI following and separated by the ampersand
    (&). If a parameter is repeated, it is treated as a multi-value for the purposes of filter comparison.
  * `uri` - The full request URI sent by the client.
  * `path` - The path portion of the request URI.
  * `query` - Returns any information contained after a `?` in a request URI.
  * `http` - To access HTTP request information.
    * `header.<header-name>` - May be used to compare the value of a particular http header. If multiple headers of 
      the same name exists, then the value is considered muli-valued. Any comparison that matches a single-value SHALL 
      be considered a match. For example `req.http.header.authorization sw bearer`.
    * `method` - The HTTP Method used to make the request (e.g. GET, POST, DELETE, PUT, PATCH).

Attributes about the current authenticated subject:
* `subject.provId` - The identifier for the provider under which the subject was authenticated. For example, this
  may be used when a subject source is `any` or `auth` but a condition applies to a specific provider.
* `subject.jwt.<claim>` - If a JWT was used, specific claims can be compared where <claim> is the name of a claim. For 
  example `subject.jwt.iss eq my.example.com`
* `subject.roles` - Roles mapped by the provider to the subject if any.
* `subject.saml.<claim>` - If a SAML assertion was used, specific claims can be compared. For example `subject.saml.iss eq my.example.com`
* `subject.prov.<name>` - Provider specific attributes related to a subject may be accessed using the `subject.prov` 
  prefix combined with a `<name>` for the provider specific attribute or claim.

Provider configuration data may be accessed using `provider.<provId>.<name>` where `<provId>` is the provId identifier 
of the configured provider and `<name>` is a configuration parameter name.

See [IDQL Providers Specification](IDQL-providers.md) for information on subject provider configuration.

----
## 4.0 IDQL Policy Statements

A set of IDQL Policy Statements is contained in an array of `idql-policies` which contains 1 or more IDQL "Policy 
statements".

Each Policy Statement consists of the following attributes:
* `id` - An unique attribute for the policy statement.
* `meta` - Metadata about the policy including versioning and descriptions.
* `subject` - A subject identifying the actors a policy is applied to.
* `actions` - A set of actions that MAY be performed or excluded
* `object` - The target assets against which policy is applied.
* `scopes` - Defines attributes which may be used as additional qualifiers against subjects, actions, actions, or in 
  conditions applied to policy.
* `condition` - A condition specifies either a `rule` or `role` for which the policy applies.

### 4.1 Id Attribute

* `id` - A unique identifier string (REQUIRED) that allows individual policies to be referenced and 
  potentially 
  indicate purpose. An `id` MAY be a [GUID](https://en.wikipedia.org/wiki/Universally_unique_identifier) or 
  simply a unique textual identifier assigned by an administrator.

### 4.2 Meta Information

The `meta` attribute is a top level policy object containing attributes for versioning and information 
organization. All meta attributes are OPTIONAL.

```yaml 
idql-policies:
- id: example-policy
  meta:
    vers: 0.1
    date: 2021-08-01T21:32:44.882Z
    etag: e180ee84f0671b1
    disp: Access policy enabling profile update
    app: CanaryBank1
    layer: external-access
  subjects:
    . . .
  actions:
    . . .
  objects:
    . . .
```

Versioning attributes include:
* `date` - A modification date expressed in `DateTime` format. Value MUST be encoded as a valid `xsd:dateTime` 
  as specified in Section 3.3.7 of XML XSD Definitions .
  [[W3C XML Schema Definition Language(XSD) 1.1 Part2: Data Types]](http://www.w3.org/TR/xmlschema11-2/) 
  and MUST include both a date and a time. A `date` SHALL have no case sensitivity or uniqueness.
* `vers` - A version identifier used to distinguish different policy versions (e.g. 1.0.1)
* `etag` - A hash value of the current policy statement per 
  [Section 2.3 of RFC7232](https://datatracker.ietf.org/doc/html/rfc7232#section-2.3). This value is often used (e.g.
  [Google Cloud Policy](https://cloud.google.com/iam/docs/policies#etag)) as a 
  request pre-condition to ensure a policy being updated has not already been altered by another entity 
  (administrative system).

Informational attributes include:
* `app` - An OPTIONAL string identifier that may be used to group policy statements pertaining to a common application.
* `disp` - An OPTIONAL string containing a description of the intent of the policy.
* `layer` - An OPTIONAL string identifier that may be used to group policy statements in a common container or 
  application layer.

### 4.3 Subject

The `subject` object (OPTIONAL) defines an authentication state (e.g. anonymous) or Identity Provider to identify a 
security entity invoking a request. If `subject` is not present, the policy rule is applied to all requests, regardless of authentication 
status (e.g. HTTP authorization is ignored).
```yaml
idql-policies:
- id: example-policy
  meta:
    . . .
  subject:
    subType: idp
    provId: myGoogleIDP
    role: goldService
  actions:
    . . .
  objects:
    . . .
```
A `subject` is a JSON or YAML object consisting of the following attributes:
* `subType` - A text value indicating the type of subject provider being referenced. Supported values include: 
  * `any` - Any subject whether authenticated or anonymous (this is the same is not specifying a subject)
  * `auth` - Any authenticated subject using any Identity Provider
  * `basic` - A subject authenticated using [HTTP Basic Auth (RFC7617)](https://datatracker.ietf.org/doc/html/rfc7617).
  * `jwt` - A subject that is authenticated by validating a
    [JWT token (RFC7519, RFC8725)](https://datatracker.ietf.org/doc/html/rfc8725) issued by an [OAuth2 Authorization
    Server (RFC6749)](https://datatracker.ietf.org/doc/html/rfc6749).
  * `op` - A subject authenticated with a JWT token issued by an [OpenID Provider](https://openid.net).
  * `saml` - A subject authenticated with an XML SAML assertion using a SAML IDP.
  * `net` - A subject identified by the requesting client's network address expressed as an IP address or 
    [CIDR (RFC1817)](https://datatracker.ietf.org/doc/html/rfc1817) value. 
    Used for access control for internal services.
  * `other` - A custom provider _[TODO: do we need this?]_
* `role` - Defines a role which the subject MUST possess for a rule to apply. A role implies a set of
  actions (i.e. permissions) that provide the ability to execute the actions specified. Multiple role values MAY be 
  specified using a comma separator. When multiple roles are specified, all values must be asserted (treated as an 
  AND).
* `members` - An array of strings representing service account, user, or group that may be matched. A member is 
  dependent on the target platform definition but often is a JWT Subject or a username or account name. If group is 
  specified, the group must be part of the inbound JWT assertion or be defined locally (e.g. in SCIM or database 
  service).

When `subType` is one of: `basic`, `jwt`, `op`, `saml`, or `other`, the attribute `authId` specifies the identifier of 
an Identity Provider configured as part of the policy project assets.
> Discuss:  do we need `subType`?  Can be inferred by the use of provId vs other attributes like `cidr`.

#### 4.3.1 JWT Sub-type
> Should this section be in the provider's configuration?

For policy scenarios where the IDP is configured externally (e.g. using OIDC or OAuth2), a subject be defined simply 
as a JWT Token with a set of configurable values and requirements.

When `subType` is set to `jwt` the following attributes are defined:
* `issuer` - A URIs representing the value of the issuer claim received in a JWT token to be accepted.
* `aud` - A URI that must match one of the "aud" values in a JWT token.
* `role_claims` - A list of claim attributes in a JWT that are to be used as `role` values for policy evaluation 
   (e.g. `["roles","scopes"]`).
* `userid` - A JWT attribute to be used as the userid in policy (e.g. used in a condition members attribute).  By 
  default `userid` is set to `sub`.

When `subType` is `net`, an attribute of `cidr` is used to specify an IP Address or network mask (CIDR).

### 4.4 Actions

Actions describe the requests, scopes, or permissions that may be performed at a particular service Object. If no 
actions are specified, it SHALL be assumed that the rule permits all actions. Actions can be logical (such as a scope) or a 
filter that compares protocol, method, and path.

```yaml
idql-policies:
- id: example-policy
  meta:
    . . .
  subjects:
    . . .
  actions:
  - name: createProfile
    actionUri: https:POST:/Users/
  - name: editProfile
    actionUri: ietf:https:PUT|PATCH:/Users/*
    condition:
      rule: adminType eq admincontractor
  objects:
    . . .
```
> TODO:  Need a couple example URIs from Google, AWS, Azure.

An action consists of the following attributes:
* `name` - An OPTIONAL unique identifier for an action.
* `actionUri` - A URI of the form `<domain-urn>:<domain-uri>` where
  * `<domain-urn>` - Is the defining domain for the action. E.g. `ietf`, `arn`, `gcp`, `azure`. For `aws`, use the AWS
    `arn` format. 
  * `<domain-uri>` - Is the domain specific formatted portion of the URI. For example, `arn` denotes Amazon Resource 
    Name and `ietf` denotes IETF based protocols (see below).
* `exclude` - When set to true, the action MAY be used to invert the action. For example, everything is permitted
  except for `https:PUT|PATCH|DELETE:/*`

URIs including paths may contain wildcards (`*`) and may contain
variables denoted by `${<variable>}` where <variable> is the variable name (e.g. calculated by a scope).

#### 4.4.1 IETF Domain URNs

For IETF protocols, the `<domain-urn>` IDQL prefix is `ietf:`. The `<domain-uri>` is formatted:
> `ietf:<protocol>:<method>:<pathSpec>?<query>`

The IETF domain is defined with:

  * `<protocol>` - Is the application protocol (e.g. FTP, HTTP, IMAP)
  * `<method>` - An associated request method (e.g. GET). Multiple methods may be specified using the `|` 
    (e.g. PUT|PATCH). A value of `*` indicates all methods.
  * `<pathSpec>` - A URI file path (per RFC3986 [Section 3.3](https://www.rfc-editor.org/rfc/rfc3986#section-3.3)) 
    which MAY include a wildcard (`*`). For example: 
    `/Users/*`.
  * `<query>` - The request query component (per RFC3986 
[Section 3.4](https://www.rfc-editor.org/rfc/rfc3986#section-3.4)).
  
#### 4.4.2 Amazon ARN Actions

The `<domain-arn>` IDQL prefix for Amazon is `arn:` which designates an Amazon Resource Name and follows AWS's [ARN 
format](https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html).
Typically, AWS uses ARNs to refer to resources, sessions, or identities. In the context of an IDQL Action, an [AWS 
Action](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html) MAY be used combined with the `arn:` prefix. So for example, the action `ec2:StartInstances` becomes 
`arn:ec2:StartInstances`. In most cases, AWS actions will be formatted:
> `arn:<product>:<action>`

Example actions:

| Type | Example |
|--- | ---|
| EC2 | `arn:ec2:StartInstances`|
| IAM | `arn:iam:ChangePassword`|
| S3 | `arn:s3:GetObject` |

As specified above, wildcards MAY be used. For example: `arn:s3:*` allows any action on an S3 object.

#### 4.4.3 Microsoft Azure URNs for Actions

The `<domain-arn>` prefix in IDQL for Microsoft Azure actions is `azure:`. Actions in Azure are combined in a [role 
definition](https://docs.microsoft.com/en-us/azure/role-based-access-control/role-definitions) which a subject must be assigned to invoke. Action URNs 
for Azure in IDQL are of the form:
> `azure:{Company}.{ProviderName}/{resourceType}/{action}`

For example:  `azure:microsoft.directory/applicationPolicies/allProperties/read` permits the requestor to read all 
properties on an application policy. 

A [contributor action](https://docs.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#contributor) 
may be defined in IDQL as:
```json lines
"actions" : [
  {"actionUri": "azure:*"},
  {"actionUri": "azure:Microsoft.Authorization/*/Delete", "exclude": true},
  {"actionUri": "azure:Microsoft.Authorization/*/Write", "exclude": true},
  {"actionUri": "azure:Microsoft.Authorization/elevateAccess/Action", "exclude": true},
  {"actionUri": "azure:Microsoft.Blueprint/blueprintAssignments/write", "exclude": true},
  {"actionUri": "azure:Microsoft.Blueprint/blueprintAssignments/delete", "exclude": true} 
]
```

#### 4.4.4 Google URNs for Actions

The `<domain-arn>` prefix for Google in IDQL is `gcp:`. Google uses roles which contain one or more permissions that 
indicate permissable actions (see [Understanding Roles](https://cloud.google.com/iam/docs/understanding-roles#predefined_roles)).

For the `actionUri`, GCP Roles are expressed as:
> `gcp:roles/<api>.<role>`

For example: `roles/file.viewer` becomes `gcp:roles/file.viewer`.


### 4.5 Object

Objects are assets in a project which are protected by policy. Objects are an identified asset combined with a path 
specification.

```yaml
idql-policies:
- id: example-policy
  meta:
    . . .
  subjects:
    . . .
  actions:
    . . .
  objects:
  - assetId: CanaryProfileService
    pathSpec: /Profile/${User:username}
```

An object consists of the following attributes:
* `assetId` - A unique URI that points to an asset where policy is to be applied.
* `pathSpec` - A string representing a path or path filter including wildcards or variables. A path may contain wildcards (`*`) and may contain
  variables denoted by `${<variable>}` where <variable> is the variable name (e.g. calculated by a scope).
* `pathRegEx` - A [Regular Expression](https://en.wikipedia.org/wiki/Regular_expression) used for matching request paths.

### 4.6 Scopes

Scopes are used to define variables which may be used in `conditions` and paths in `actions` and `objects`.

Scope variables may also be returned to applications instead of an allow/deny boolean response.  
_[TODO: How is this expressed?]_

```yaml
idql-policies:
- id: example-policy
  meta:
    . . .
  subjects:
    . . .
  actions:
    . . .
  objects:
  - assetId: CanaryProfileService
    pathSpec: /Profile/*
  scopes:
  - name: adminType
    value: admin-contractor
    condition:
      rule: User:employeeType eq contract
      action: allow
  - name: workCountry
    value: ${Users:addresses[type eq work].country}
```

A scope consists of the following attributes:
* `name` - The name of a variable to define. Scope name values SHOULD avoid naming conflicts with other attribute 
  sources. In the event of a name conflict, the name defined in scope SHALL take precedence.
* `value` - The value to be assigned. The value may be a static string or integer, or may be a string using variable 
  substitution denoted by `${<variable>}` where <variable> is the variable name.  For example: `"admin-${User:employeeType}"`
_[TODO: should multi-value and other types be allowed? E.g. use square brackets?]_

Note in the above scope example:
* workCountry is a scope variable `workCountry` that is defined as the employee's work
address. The qualifier `[type eq work]` selects the work address value from the multi-valued attribute `addresses` and
assigns the value of sub-attribute `country`.
* `adminType` is assigned `admin-contractor` if the User's `employeeType` attribute is equal to `contract`.

### 4.7 Condition
Conditions are used to qualify whether a subject, action, or object is to be applied. 

```yaml
idql-policies:
- id: example-policy
  meta:
    . . .
  subject:
    subType: idp
    provId: myGoogleIDP
  actions:
  - name: createProfile
    actionUri: https:POST:/Users/
  - name: editProfile
    actionUri: https:PUT|PATCH:/Users/*
  condition:
    rule: role eq admincontractor and subject.jwt.iss eq oidc.strata.io
  objects:
    . . .
```

A condition consists of a `role` or a `rule` and an optional `action`:

* `rule` - A matching filter that uses a SCIM filter value as specified in Section
  [3.4.2.2 of RFC7644](https://datatracker.ietf.org/doc/html/rfc7644#section-3.4.2.2). In addition to using SCIM 
  attribute names for User objects, each provider and object may define additional contextual (client ip, path, etc.) 
  attributes that MAY be used during policy evaluation. These may be referred to by their simple name. Scope attribute 
  names MAY also be 
  referred to by their name. For example: `req.ip eq 192.168.1.10`.   Filter values MAY be URL-encoded per 
  [Section 2.1 of RFC3986](https://datatracker.ietf.org/doc/html/rfc3986#section-2.1).
* `action` - Indicates the desired effect of the condition. When omitted, the default is `allow`. Valid values are:
  * `allow` - Proceeds if there is a match.   
  * `deny` - Negates the outcome if there is a match.
  * `audit` - The rule is not enforced, but processing outcome is logged.

---

## 5.0 Appendix A - Use Cases

### 5.1 General RBAC Policy Examples

This use case will attempt to map the example given in the introduction to each platform.

-----
#### 5.1.1 Google Policy

Considering the example:
```json
{
  "id": "EditProfileGoogleUpdate AdminContractor",
  "meta": {
    "vers": "0.1",
    "date": "2021-08-01 21:32:44 UTC",
    "disp": "Access policy enabling contract staff to edit profiles",
    "app": "CanaryBank1",
    "layer": "Browser"
  },
  "subject": {
    "subType": "op",
    "provId": "myGoogleIDP"
  },
  "actions": [
    {
      "name": "editProfile",
      "actionUri": "accountEdit"
    }
  ],
  "object": {
    "assetId": "CanaryProfileService",
    "pathSpec": "/Profile/*"
  },
  "condition": {
    "rule": "User:employeeType eq contract",
    "action": "allow"
  }
}
```

In the assets data, it is assumed that the configuration information stores the following variables for the object
CanaryProfileService`.
```json
{
  "id": "CanaryProfileService",
  "type": "GCP.compute",
  "projectid": "xyz",
  "region": "",
  "resourceid": "55ec91ba47ba4f44adf0ef3b748e430f"
}
```

The policy to be applied would be:
```json lines
HTTP POST https://iap.googleapis.com/v1/projects/xyz/iap_web/compute/services/55ec91ba47ba4f44adf0ef3b748e430f
:setIamPolicy
{
  "policy": {
    "version": 3,
    "bindings": [
      {
        "role": "roles/iap.httpsResourceAccessor",
        "members": [
          "domain:canarybank.io"
        ],
        "condition": {
          "expression": "request.path.startsWith(\"/Profile\") && account.properties.employeeType == \"contractor\""
        }
      }
    ]
  }
}
```

> Note: It is not clear that the CEL expression "account.properties.employeeType" is possible with IAP.

   
----
#### 5.1.2 AWS API Policy

Following the same IDQL example in the Google example (Section 7.1.1). The asset information might look like:
In the assets data, it is assumed that the configuration information stores the following variables for the object
CanaryProfileService`.
```json
{
  "id": "CanaryProfileService",
  "type": "aws",
  "account-id": "xyz",
  "api-id": "a1234567890",
  "region": "us-east-1",
  "stage-name": "",
  "http-verb": "",
  "resoource-path-specifier": "/Profile/*"
}
```

Likewise, the subject provider `myGoogleIdp` maps back to a federated OIDC provider whose URI is:  `idp.canarybank.io`.

An AWS resource is typically defined by:

`arn:aws:execute-api:region:account-id:api-id/stage-name/HTTP-VERB/resource-path-specifier`

A resource policy may be attached to an 
[API Gateway](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-policy-language
-overview.html).  Also see 
[API Gateway ARM Reference](https://docs.aws.amazon.com/apigateway/latest/developerguide/arn-format-reference.html).

```json
{
    "Version": "0.1",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
              "Federated": "idp.canarybank.io"
            },
            "Action": "execute-api:Invoke",
            "Resource": "arn:aws:execute-api:us-east-1:xyz:a1234567890/*/*/Profile/*"
        }]
}
```
> TODO: This policy does not implement the condition employeeType eq contractor.

----
#### 5.1.3 Azure App Role

Following the same IDQL example in the Google example (Section 7.1.1). The asset information might look like:
In the assets data, it is assumed that the configuration information stores the following variables for the object
CanaryProfileService`.
```json
{
  "id": "CanaryProfileService",
  "type": "azure.waf",
  "subscription": "s1234567890",
  "resourceGroup": "xyz",
  "api-id": "8763f1c4-0000-0000-0000-158e9ef97d6a",
  "location": "us-east-1",
  "stage-name": "",
  "resoource": "/Profile/*"
}
```
In Azure, users and groups are assigned roles in the directory using Graph.  You then can add User or Application roles 
to an application. The azure case is unclear for a federated provider. 

The following policy assigns a role to an application.  When the User is authenticated, the roles claim must include 
the value `accountEdit`.

> TODO: It is unclear how Azure would enforce the employeeType eq contractor. Presumably this is done in the AD 
> graph rather than handled dynamically.

```json
"appId": "8763f1c4-0000-0000-0000-158e9ef97d6a",
"appRoles": [
    {
      "allowedMemberTypes": [
        "User"
      ],
      "displayName": "editProfile",
      "id": "d1c2ade8-0000-0000-0000-6d06b947c66f",
      "isEnabled": true,
      "description": "Access policy enabling contract staff to edit profiles",
      "value": "accountEdit"
    }
  ],
"availableToOtherTenants": false,
```
