# IDQL Conventions and Definitions

All IDQL specifications use the following conventions and definitions.

## Intended Audience

These specifications are written for implementers of IDQL systems, editors, and gateways as a common source of 
authority for the IDQL "language".

## Notational Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [RFC2119](https://datatracker.ietf.org/doc/html/rfc2119).  These key
words are capitalized when used to unambiguously specify requirements
of the protocol or application features and behavior that affect the
interoperability and security of implementations.  When these words
are not capitalized, they are meant in their natural-language sense.

For purposes of readability, examples are not URL encoded.
Implementers MUST percent-encode URLs as described in Section 2.1 of
[RFC3986](https://datatracker.ietf.org/doc/html/rfc3986).

Throughout these documents, figures may contain spaces and extra line
wrapping to improve readability and accommodate space limitations.
Similarly, some URIs contained within examples have been shortened, along with irrelevant content
for space and readability reasons and is indicated by ". . ." in figures.

Where attributes or parameters are discussed, angle-brackets are used to denote substitution. 
For example `subjects.http.header.<name>` 
means name can be replaced with the name of an HTTP Header. For example `subjects.http.header.authorization`.

## Schema

An IDQL statement may be formatted either in YAML or JSON format. Because all JSON can be formatted as YAML, these
specifications are expressed in JSON format. All JSON objects will be defined using [JSON Schema](https://json-schema.org).

## API Descriptions

IDQL related APIs will be described using the [OpenAPI 3 Specification](https://github.com/OAI/OpenAPI-Specification) 
(formerly Swagger).

## Terminology


* _Action_ - An action that a `Subject` may perform. Actions are defined by the target `object` depending on its 
capabilities.
* _Asset_ - An asset is simply any componenet that is identifiable in a cloud native infrastructure. It may be an
  Identity Provider or it may be the target where a policy may be deployed or intended to impact.
* _Attribute_ - An attribute is a variable that may be available for a policy rule to reference. Attributes may
  contain configuration information, request information, or claims provided by an Identity Provider.
* _Claim_ - A claim is an Attribute about a user or other security subject. The term "claim" is used to suggest that
  the attribute may not be verified and its authenticity or accuracy may be in question. For the purpose of policy
  syntax, a claim is an attribute.
* _Condition_ - A condition may be applied in order to match an IDQL rule to a `Subject`, `Action`, or `Object`.
* _Object_ - A target entity where policy can be applied. An `object` typically has one or more `action` associated 
with it.
* _Scope_ - A special condition that results in a non-binary result for a policy. For example a use case "Alice is 
permitted administrator access to US Data" would require a `scope` of "US Data".
* _Policy Decision Point_ - Is a shared service where a requestor may ask for a policy decision given a supplied 
  request information.
* _Policy Enforcement Point_ - Describes the location where the result of a policy decision is acted upon. For example 
  an identity enable proxy may reject an HTTP request or pass the request on to an intended endpoint.
* _Policy Gateway_ - Is an IDQL service endpoint that is intended to map and deploy IDQL policy with a target Asset.
* _Subject_ - A security entity that initiates a request to perform an `action`.
