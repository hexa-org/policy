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
Similarly, some URIs contained within examples have been shortened
for space and readability reasons (as indicated by "...").

## Schema

An IDQL statement may be formatted either in YAML or JSON format. Because all JSON can be formatted as YAML, these
specifications are expressed in JSON format. All JSON objects will be defined using [JSON Schema](https://json-schema.org).

## API Descriptions

IDQL related APIs will be described using the [OpenAPI 3 Specification](https://github.com/OAI/OpenAPI-Specification) 
(formerly Swagger).

## Terminology

* `Subject` - A security entity that initiates a request to perform an `action`.
* `Action` - An action that a `Subject` may perform. Actions are defined by the target `object` depending on its 
capabilities.
* `Object` - A target entity where policy can be applied. An `object` typically has one or more `action` associated 
with it.
* `Scope` - A special condition that results in a non-binary result for a policy. For example a use case "Alice is 
permitted administrator access to US Data" would require a `scope` of "US Data".
* `Condition` - A condition may be applied in order to match an IDQL rule to a `Subject`, `Action`, or `Object`.