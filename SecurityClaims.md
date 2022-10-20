We summarize here all the security claims and important modeling informations from the draft 17 of the lake edhoc protocol https://datatracker.ietf.org/doc/html/draft-ietf-lake-edhoc-17.

[p6]  EDHOC authenticated with signature keys is
   built on a variant of the SIGMA protocol which provides identity
   protection of the initiator (SIGMA-I) against active attackers, 
   
[p7] 
   EDHOC is designed to encrypt and integrity protect as much
   information as possible.   
   
[p7] `Transcript hashes (hashes of message data) TH_2, TH_3, TH_4 used
      for key derivation and as additional authenticated data.`


[p8] All EDHOC messages
   are CBOR Sequences [RFC8742], and are deterministically encoded.


[p8]    The Initiator can derive symmetric application keys after creating
   EDHOC message_3, see Section 4.2.1.  Protected application data can
   therefore be sent in parallel or together with EDHOC message_3.
   EDHOC message_4 is typically not sent.


[p17]   As stated in Section 3.1 of [RFC9052], applications MUST NOT assume
   that 'kid' values are unique and several keys associated with a 'kid'
   may need to be checked before the correct one is found.  Applications
   might use additional information such as 'kid context' or lower
   layers to determine which key to try first.  Applications should
   strive to make ID_CRED_x as unique as possible, since the recipient
   may otherwise have to try several keys.


[p27]  If the processing fails for some reason then, typically, an error
   message is sent, the protocol is discontinued, and the protocol state
   erased.  
   
[p34]    The Initiator SHOULD NOT persistently store PRK_out or application
   keys until the Initiator has verified message_4 or a message
   protected with a derived application key, such as an OSCORE message,
   from the Responder.  This is similar to waiting for acknowledgement
   (ACK) in a transport protocol.


[p35]   After verifying message_3, the Responder can compute PRK_out, see
   Section 4.1.3, derive application keys using the EDHOC-Exporter
   interface, see Section 4.2.1, persistently store the keying material,
   and send protected application data.


[p42]  EDHOC inherits its security properties from the theoretical SIGMA-I
   protocol [SIGMA].  Using the terminology from [SIGMA], EDHOC provides
   forward secrecy, mutual authentication with aliveness, consistency,
   and peer awareness.  `As described in [SIGMA], message_3 provides peer
   awareness to the Responder` while message_4 provides peer awareness to
   the Initiator.  By including the authentication credentials in the
   transcript hash, EDHOC protects against Duplicate Signature Key
   Selection (DSKS)-like identity mis-binding attack that the MAC-then-
   Sign variant of SIGMA-I is otherwise vulnerable to.

   As described in [SIGMA], different levels of identity protection are
   provided to the Initiator and the Responder.  `EDHOC provides identity
   protection of the Initiator against active attacks` and identity
   protection of the Responder against passive attacks.  An active
   attacker can get the credential identifier of the Responder by
   eavesdropping on the destination address used for transporting
   message_1 and send its own message_1 to the same address.  The roles
   should be assigned to protect the most sensitive identity/identifier,
   typically that which is not possible to infer from routing
   information in the lower layers.

   EDHOC messages might change in transit due to a noisy channel or
   through modification by an attacker.  `Changes in message_1 and
   message_2 (except PAD_2) are detected when verifying
   Signature_or_MAC_2.  Changes to PAD_2 and message_3 are detected when
   verifying CIPHERTEXT_3. ` Changes to message_4 are detected when
   verifying CIPHERTEXT_4.

[p43] `Compared to [SIGMA], EDHOC adds an explicit method type and expands
   the message authentication coverage to additional elements such as
   algorithms, external authorization data, and previous plaintext
   messages.`  This protects against an attacker replaying messages or
   injecting messages from another session.

   EDHOC also adds selection of connection identifiers and downgrade
   protected negotiation of cryptographic parameters, i.e., an attacker
   cannot affect the negotiated parameters.  A single session of EDHOC
   does not include negotiation of cipher suites, but it enables the
   Responder to verify that the selected cipher suite is the most
   preferred cipher suite by the Initiator which is supported by both
   the Initiator and the Responder.

   As required by [RFC7258], IETF protocols need to mitigate pervasive
   monitoring when possible.  EDHOC therefore only supports methods with
   ephemeral Diffie-Hellman and provides a key update function (see
   Appendix J) for lightweight application protocol rekeying.  `Either of
   these provide forward secrecy, in the sense that compromise of the
   private authentication keys does not compromise past session keys,
   and compromise of a session key does not compromise past session
   keys.`  Frequently re-running EDHOC with ephemeral Diffie-Hellman
   forces attackers to perform dynamic key exfiltration where the
   attacker must have continuous interactions with the collaborator,
   which is a significant complication.

   To limit the effect of breaches, it is important to limit the use of
   symmetrical group keys for bootstrapping.  EDHOC therefore strives to
   make the additional cost of using raw public keys and self-signed
   certificates as small as possible.  Raw public keys and self-signed
   certificates are not a replacement for a public key infrastructure
   but SHOULD be used instead of symmetrical group keys for
   bootstrapping.

   `Compromise of the long-term keys (private signature or static DH
   keys) does not compromise the security of completed EDHOC exchanges.`
   Compromising the private authentication keys of one party lets an
   active attacker impersonate that compromised party in EDHOC exchanges
   with other parties but does not let the attacker impersonate other
   parties in EDHOC exchanges with the compromised party.  `Compromise of
   the long-term keys does not enable a passive attacker to compromise
   future session keys.`  Compromise of the HDKF input parameters (ECDH
   shared secret) leads to compromise of all session keys derived from
   that compromised shared secret.  `Compromise of one session key does
   not compromise other session keys.`  Compromise of PRK_out leads to
   compromise of all keying material derived with the EDHOC-Exporter.


[p44] Based on the cryptographic algorithms requirements Section 8.3, EDHOC
   provides a minimum of 64-bit security against online brute force
   attacks and a minimum of 128-bit security against offline brute force
   attacks.  To break 64-bit security against online brute force an
   attacker would on average have to send 4.3 billion messages per
   second for 68 years, which is infeasible in constrained IoT radio
   technologies.  A forgery against a 64-bit MAC in EDHOC breaks the
   security of all future application data, while a forgery against a
   64-bit MAC in the subsequent application protocol (e.g., OSCORE
   [RFC8613]) typically only breaks the security of the data in the
   forged packet.

   As the EDHOC protocol is terminated when verification fails, the
   security against online attacks is given by the sum of the strength
   of the verified signatures and MACs (including MAC in AEAD).  As an
   example, if EDHOC is used with method 3, cipher suite 2, and
   message_4, the Responder is authenticated with 128-bit security
   against online attacks (the sum of the 64-bit MACs in message_2 and
   message_4).  The same principle applies for MACs in an application
   protocol keyed by EDHOC as long as EDHOC is rerun when verification
   of the first MACs in the application protocol fail.  As an example,
   if EDHOC with method 3 and cipher suite 2 is used as in Figure 2 of
   [I-D.ietf-core-oscore-edhoc], 128-bit mutual authentication against
   online attacks can be achieved after completion of the first OSCORE
   request and response.

   `After sending message_3, the Initiator is assured that no other party
   than the Responder can compute the key PRK_out.`  While the Initiator
   can securely send protected application data, the Initiator SHOULD
   NOT persistently store the keying material PRK_out until the
   Initiator has verified an OSCORE message or message_4 from the
   Responder. `After verifying message_3, the Responder is assured that
   an honest Initiator has computed the key PRK_out.`  The Responder can
   securely derive and store the keying material PRK_out, and send
   protected application data.

   External authorization data sent in message_1 (EAD_1) or message_2
   (EAD_2) should be considered unprotected by EDHOC, see Section 8.5.
   EAD_2 is encrypted but the Responder has not yet authenticated the
   Initiator and the encryption does not provide confidentiality against
   active attacks.

   External authorization data sent in message_3 (EAD_3) or message_4
   (EAD_4) is protected between Initiator and Responder by the protocol,
   but note that EAD fields may be used by the application before the
   message verification is completed, see Section 3.8.  Designing a
   secure mechanism that uses EAD is not necessarily straightforward.
   This document only provides the EAD transport mechanism, but the
   
   
   [p45]   problem of agreeing on the surrounding context and the meaning of the
   information passed to and from the application remains.  Any new uses
   of EAD should be subject to careful review.

   Key compromise impersonation (KCI): `In EDHOC authenticated with
   signature keys, EDHOC provides KCI protection against an attacker
   having access to the long-term key or the ephemeral secret key.  With
   static Diffie-Hellman key authentication, KCI protection would be
   provided against an attacker having access to the long-term Diffie-
   Hellman key, but not to an attacker having access to the ephemeral
   secret key.  Note that the term KCI has typically been used for
   compromise of long-term keys, and that an attacker with access to the
   ephemeral secret key can only attack that specific session.`

   Repudiation: `If an endpoint authenticates with a signature, the other
   endpoint can prove that the endpoint performed a run of the protocol
   by presenting the data being signed as well as the signature itself.
   With static Diffie-Hellman key authentication, the authenticating
   endpoint can deny having participated in the protocol.`

   Two earlier versions of EDHOC have been formally analyzed [Norrman20]
   [Bruni18] and the specification has been updated based on the
   analysis.


[p45] 
   The SIGMA protocol requires that the encryption of message_3 provides
   confidentiality against active attackers and EDHOC message_4 relies
   on the use of authenticated encryption.  Hence the message
   authenticating functionality of the authenticated encryption in EDHOC
   is critical: authenticated encryption MUST NOT be replaced by plain
   encryption only, even if authentication is provided at another level
   or through a different mechanism.

   To reduce message overhead EDHOC does not use explicit nonces and
   instead relies on the ephemeral public keys to provide randomness to
   each session.  A good amount of randomness is important for the key
   generation, to provide liveness, and to protect against interleaving
   attacks.  For this reason, the ephemeral keys MUST NOT be used in
   more than one EDHOC message, and both parties SHALL generate fresh
   random ephemeral key pairs.  Note that an ephemeral key may be used
   to calculate several ECDH shared secrets.  When static Diffie-Hellman
   authentication is used the same ephemeral key is used in both
   ephemeral-ephemeral and ephemeral-static ECDH.

   As discussed in [SIGMA], the encryption of message_2 does only need
   to protect against passive attacker as active attackers can always
   get the Responder's identity by sending their own message_1.  EDHOC
   
   
 [p46] uses the Expand function (typically HKDF-Expand) as a binary additive
   stream cipher which is proven secure as long as the expand function
   is a PRF.  HKDF-Expand is not often used as a stream cipher as it is
   slow on long messages, and most applications require both IND-CCA
   confidentiality as well as integrity protection.  For the encryption
   of message_2, any speed difference is negligible, IND-CCA does not
   increase security, and integrity is provided by the inner MAC (and
   signature depending on method).

   Requirements for how to securely generate, validate, and process the
   ephemeral public keys depend on the elliptic curve.  For X25519 and
   X448, the requirements are defined in [RFC7748].  For secp256r1,
   secp384r1, and secp521r1, the requirements are defined in Section 5
   of [SP-800-56A].  For secp256r1, secp384r1, and secp521r1, at least
   partial public-key validation MUST be done.

   As noted in Section 12 of [RFC9052] the use of a single key for
   multiple algorithms is strongly discouraged unless proven secure by a
   dedicated cryptographic analysis.  In particular this recommendation
   applies to using the same private key for static Diffie-Hellman
   authentication and digital signature authentication.  A preliminary
   conjecture is that a minor change to EDHOC may be sufficient to fit
   the analysis of secure shared signature and ECDH key usage in
   [Degabriele11] and [Thormarker21].

   The property that a completed EDHOC exchange implies that another
   identity has been active is upheld as long as the Initiator does not
   have its own identity in the set of Responder identities it is
   allowed to communicate with.  In Trust on first use (TOFU) use cases,
   see Appendix D.5, the Initiator should verify that the Responder's
   identity is not equal to its own.  Any future EHDOC methods using
   e.g., pre-shared keys might need to mitigate this in other ways.
   However, an active attacker can gain information about the set of
   identities an Initiator is willing to communicate with.  If the
   Initiator is willing to communicate with all identities except its
   own an attacker can determine that a guessed Initiator identity is
   correct.  To not leak any long-term identifiers, it is recommended to
   use a freshly generated authentication key as identity in each
   initial TOFU exchange.   


[p48]  The Initiator and the Responder must make sure that unprotected data
   and metadata do not reveal any sensitive information.  This also
   applies for encrypted data sent to an unauthenticated party.  In
   particular, it applies to EAD_1, ID_CRED_R, EAD_2, and error
   messages.  Using the same EAD_1 in several EDHOC sessions allows
   passive eavesdroppers to correlate the different sessions.  Note that
   even if ead_value is encrypted outside of EDHOC, the ead_label in
   EAD_1 is revealed to passive attackers and the ead_label in EAD_2 is
   revealed to active attackers.  Another consideration is that the list
   of supported cipher suites may potentially be used to identify the
   application.  The Initiator and the Responder must also make sure
   that unauthenticated data does not trigger any harmful actions.  In
   particular, this applies to EAD_1 and error messages.

   An attacker observing network traffic may use connection identifiers
   sent in clear in EDHOC or the subsequent application protocol to
   correlate packets sent on different paths or at different times.  The
   attacker may use this information for traffic flow analysis or to
   track an endpoint.  Application protocols using connection
   identifiers from EDHOC SHOULD provide mechanisms to update the
   connection identifier and MAY provide mechanisms to issue several
   simultaneously active connection identifiers.  See [RFC9000] for a
   non-constrained example of such mechanisms.  Connection identifiers
   can e.g., be chosen randomly among the set of unused 1-byte
   connection identifiers.  Connection identity privacy mechanisms are
   only useful when there are not fixed identifiers such as IP address
   or MAC address in the lower layers.


[p50]  All private keys, symmetric keys, and IVs MUST be secret.
   Implementations should provide countermeasures to side-channel
   attacks such as timing attacks.  Intermediate computed values such as
   ephemeral ECDH keys and ECDH shared secrets MUST be deleted after key
   derivation is completed.


[p51] The private authentication keys MUST be kept secret, only the
   Responder SHALL have access to the Responder's private authentication
   key and only the Initiator SHALL have access to the Initiator's
   private authentication key.


[p78] 
   EDHOC might be used without authentication by allowing the Initiator
   or Responder to communicate with any identity except its own.  Note
   that EDHOC without mutual authentication is vulnerable to man-in-the-
   middle attacks and therefore unsafe for general use.  However, it is
   possible to later establish a trust relationship with an unknown or
   not-yet-trusted endpoint.  Some examples:

   *  The EDHOC authentication credential can be verified out-of-band at
      a later stage.

   * ` The EDHOC session key can be bound to an identity out-of-band at a
      later state.`

   * ` Trust on first use (TOFU) can be used to verify that several EDHOC
      connections are made to the same identity.`  TOFU combined with
      proximity is a common IoT deployment model which provides good
      security if done correctly.  Note that secure proximity based on
      short range wireless technology requires very low signal strength
      or very low latency.


[p81] An EDHOC implementation MAY store the previously sent EDHOC message
   to be able to resend it.

   In principle, if the EDHOC implementation would deterministically
   regenerate the identical EDHOC message previously sent, it would be
   possible to instead store the protocol state to be able to recreate
   and resend the previously sent EDHOC message.  However, even if the
   protocol state is fixed, the message generation may introduce
   differences which compromises security.  For example, in the
   generation of message_3, if I is performing a (non-deterministic)
   ECDSA signature (say, method 0 or 1, cipher suite 2 or 3) then
   PLAINTEXT_3 is randomized, but K_3 and IV_3 are the same, leading to
   a key and nonce reuse.

  The EDHOC implementation MUST NOT store previous protocol state and
   regenerate an EDHOC message if there is a risk that the same key and
   IV are used for two (or more) distinct messages.


[p83] To provide forward secrecy in an even more efficient way than re-
   running EDHOC, this section specifies the optional function EDHOC-
   KeyUpdate in terms of EDHOC-KDF and PRK_out.
