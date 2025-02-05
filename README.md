# Dynamic Token Status List

When using status management solution like a normal status list, the entries are static and allow a tracking of the status of the presented credentials by the relying party. Short lived credentials and status assertion are have be issued a lot of time without the usage to not be able to be monitored by the status manager. Also these both options do not work offline when not cached before.

The dynamic status list approach is privacy friendly approach where the index in the status list is dynamic to reduce traceability by the relying party.

## Privacy with time based tokens

The dynamic status list is in general a list of time based hashed. The hash is calculated with a time based token and the credential id as input. The secret to calculate the time based token is only known by the status manager and the holder. The relying party can only verify the status of the credential by the time based token once presented by the holder. Only during this time frame the relying party can verify the status of the credential.

## Container

The dynamic list can be managed in multiple ways. In all ways a JsonWebToken is used to hold the information. The type of the container has no impact on the privacy aspect, but the required resources and the way of verification.

### CL

The values are added as a list that is used for matching. While this approach is quite simple, it will consume a lot of resources when number of entries grows. The approach is similar to a CRL, but instead of publishing the revoked ones, a proof of issuance is published that has to be sent from the wallet to the relying party.

### Cascading Bloom filter (Deprecated)

The values are added to a bloom filter. This approach is more efficient in terms of used resources, but comes with the risk of false positives. After some tests it turned out that it's quite easy to generate a proof that marks a revoked credential is valud (easy = less than 10 seconds).
Because of this the old containers are removed from this repo.
