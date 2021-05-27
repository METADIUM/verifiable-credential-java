package com.metadium.vc;

import java.io.IOException;
import java.net.URI;
import java.text.ParseException;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Verifiable credential or presentation JWTs sign and verify
 * @see <a href="https://w3c.github.io/vc-data-model/#proof-formats">Verifiable Credentials Data Model -Proof Formats</a>
 * @author mansud
 *
 */
@Deprecated
public class VerifiableSignedJWT {
	private static final String JSONLD_KEY_CREDENTIAL_SUBJECT_ID = "id";
	private static final String JWT_HEADER_NONCE = "nonce";
	private static final String JWT_PAYLOAD_VERIFIABLE_CREDENTIAL = "vc";
	private static final String JWT_PAYLOAD_VERIFIABLE_PRESENTATION = "vp";
	
	/**
	 * Sign verifiable
	 * @param verifiable verifiable credential or presentation
	 * @param algorithm JWS algorithm. recommend {@link JWSAlgorithm#ES256K}
	 * @param kid key id (DID) of signer. "did:meta:0x384394#key1"
	 * @param nonce to avoid replay attack
	 * @param signer signer object. recommend {@link ECDSASigner}
	 * @return signed verifiable
	 * @throws JOSEException 
	 */
	public static SignedJWT sign(Verifiable verifiable, JWSAlgorithm algorithm, String kid, String nonce, JWSSigner signer) throws JOSEException  {
		JWTClaimsSet claimsSet;
		if (verifiable instanceof VerifiableCredential) {
			claimsSet = credentialToJWT((VerifiableCredential)verifiable, nonce);
		}
		else if (verifiable instanceof VerifiablePresentation) {
			claimsSet = presentationToJWT((VerifiablePresentation)verifiable, nonce);
		}
		else {
			return null;
		}
		
		// sign to JWT
		signer.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
		JWSHeader jwsHeader = new JWSHeader(algorithm, JOSEObjectType.JWT, null, null, null, null, null, null, null, null, kid, null, null);
		SignedJWT jwts = new SignedJWT(jwsHeader, claimsSet);
		jwts.sign(signer);
		
		return jwts;
	}
	
	public static SignedJWT sign(Verifiable verifiable, String kid, String nonce, ECDSASigner signer) throws JOSEException  {
		return sign(verifiable, JWSAlgorithm.ES256K, kid, nonce, signer);
	}
	
	/**
	 * signed verifiable to Verifiable
	 * @param signedVerifiable signed verifiable
	 * @return verifiable object
	 * @throws ParseException invalid signed verifiable
	 * @throws JOSEException
	 */
	public static Verifiable toVerifiable(SignedJWT signedVerifiable) throws ParseException, JOSEException {
		JWTClaimsSet claims = signedVerifiable.getJWTClaimsSet();
		if (claims.getClaim(JWT_PAYLOAD_VERIFIABLE_CREDENTIAL) != null) {
			return toCredential(claims);
		}
		else if (claims.getClaim(JWT_PAYLOAD_VERIFIABLE_PRESENTATION) != null) {
			return toPresentation(claims);
		}
		return null;
	}
	
	/**
	 * convert from JWT to Verifiable credential.
	 * @see <a href="https://w3c.github.io/vc-data-model/#jwt-decoding">JWT Decoding</a>
	 * @param claimsSet JWT
	 * @return verifiable credential
	 */
	@SuppressWarnings("unchecked")
	private static VerifiableCredential toCredential(JWTClaimsSet claimsSet) {
		String id = claimsSet.getJWTID();
		Date expireDate = claimsSet.getExpirationTime();
		String issuer = claimsSet.getIssuer();
		Date issuedDate = claimsSet.getIssueTime();
		String subject = claimsSet.getSubject();
		Map<String, Object> vcClaim = (Map<String, Object>)claimsSet.getClaim(JWT_PAYLOAD_VERIFIABLE_CREDENTIAL);
		
		VerifiableCredential vc = new VerifiableCredential(vcClaim);
		if (id != null) {
			vc.setId(URI.create(id));
		}
		if (expireDate != null) {
			vc.setExpirationDate(expireDate);
		}
		if (issuer != null) {
			Object issuerObject = vcClaim.get(VerifiableCredential.JSONLD_KEY_ISSUSER);
			if (issuerObject instanceof Map) {
				vc.setIssuer(URI.create(issuer), (Map<String, Object>)issuerObject);
			}
			else {
				vc.setIssuer(URI.create(issuer));
			}
		}
		if (issuedDate != null) {
			vc.setIssuanceDate(issuedDate);
		}
		if (subject != null) {
			Object credentialSubject = vc.getCredentialSubject();
			if (credentialSubject instanceof Map) {
				((Map<String, Object>)credentialSubject).put(JSONLD_KEY_CREDENTIAL_SUBJECT_ID, subject);
			}
		}
		
		return vc;
	}
	
	/**
	 * convert from JWT to Verifiable presentation.
	 * @see <a href="https://w3c.github.io/vc-data-model/#jwt-decoding">JWT Decoding</a>
	 * @param claimsSet JWT
	 * @return verifiable presentation
	 */
	@SuppressWarnings("unchecked")
	private static VerifiablePresentation toPresentation(JWTClaimsSet claimsSet) {
		String id = claimsSet.getJWTID();
		String holder = claimsSet.getIssuer();
		
		Object vpClaim = claimsSet.getClaim(JWT_PAYLOAD_VERIFIABLE_PRESENTATION);
		
		VerifiablePresentation vp = new VerifiablePresentation((Map<String, Object>)vpClaim);
		if (id != null) {
			vp.setId(URI.create(id));
		}
		if (holder != null) {
			vp.setHolder(URI.create(holder));
		}
		
		return vp;
	}
	
	/**
	 * Convert from verifiable credential to JWT
	 * @param vc	verifiable credential
	 * @param nonce to avoid replay attack
	 * @return JWT
	 */
	@SuppressWarnings("unchecked")
	private static JWTClaimsSet credentialToJWT(VerifiableCredential vc, String nonce) {
		LinkedHashMap<String, Object> vcObject = deepCopy(vc.getJsonObject());

		// From verifiable credential, extract parameters in JWT header
		URI jti = vc.getId();
		Date expireDate = vc.getExpriationDate();
		URI issuer = vc.getIssuer();
		Date issuedDate = vc.getIssunaceDate();
		Object credentialSubject = vc.getCredentialSubject();
		URI subject = null;
		if (credentialSubject instanceof Map) {
			String id = (String)((Map<String, Object>)credentialSubject).get(JSONLD_KEY_CREDENTIAL_SUBJECT_ID);
			if (id != null) {
				subject = URI.create(id);
				// remove id of credential subject
				((Map<String, Object>)vcObject.get(VerifiableCredential.JSONLD_KEY_CREDENTIAL_SUBJECT)).remove(JSONLD_KEY_CREDENTIAL_SUBJECT_ID);
			}
		}
		
		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
		if (jti != null) {
			// move id to jwt.jti
			builder.jwtID(jti.toString());
			vcObject.remove(Verifiable.JSONLD_KEY_ID);
		}
		if (expireDate != null) {
			// move expire date to jwt.exp
			builder.expirationTime(expireDate);
			vcObject.remove(VerifiableCredential.JSONLD_KEY_EXPIRATION_DATE);
		}
		if (issuer != null) {
			// move issuer to jwt.iss
			builder.issuer(issuer.toString());
			
			vcObject.remove(VerifiableCredential.JSONLD_KEY_ISSUSER);
			Map<String, Object> issuerObject = vc.getIssuerObject();
			if (issuerObject != null) {
				vcObject.put(VerifiableCredential.JSONLD_KEY_ISSUSER, issuerObject);
			}
		}
		if (issuedDate != null) {
			// move issue time to jwt.nbf
			builder.issueTime(issuedDate);
			vcObject.remove(VerifiableCredential.JSONLD_KEY_ISSUANCE_DATE);
		}
		if (subject != null) {
			// set subject credentialSubject.id
			builder.subject(subject.toString());
		}
		if (nonce != null) {
			builder.claim(JWT_HEADER_NONCE, nonce);
		}
		
		builder.claim(JWT_PAYLOAD_VERIFIABLE_CREDENTIAL, vcObject);
		
		return builder.build();
	}

	/**
	 * Convert from verifiable presentation to JWT
	 * @param vc	verifiable presentation
	 * @param nonce to avoid replay attack
	 * @return JWT
	 * @throws IOException 
	 */
	private static JWTClaimsSet presentationToJWT(VerifiablePresentation vp, String nonce) {
		LinkedHashMap<String, Object> vpObject = deepCopy(vp.getJsonObject());
		 
		// From verifiable credential, extract parameters in JWT header
		URI jti = vp.getId();
		URI holder = vp.getHolder();
		
		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
		if (jti != null) {
			// move id to jwt.jti
			builder.jwtID(jti.toString());
			vpObject.remove(Verifiable.JSONLD_KEY_ID);
		}
		if (holder != null) {
			builder.issuer(holder.toString());
			vpObject.remove(VerifiablePresentation.JSONLD_KEY_HOLDER);
		}
		if (nonce != null) {
			builder.claim(JWT_HEADER_NONCE, nonce);
		}
		
		builder.claim(JWT_PAYLOAD_VERIFIABLE_PRESENTATION, vpObject);
		
		return builder.build();
	}

	/**
	 * Map deep copy
	 * @param src
	 * @return
	 */
	private static LinkedHashMap<String, Object> deepCopy(LinkedHashMap<String, Object> src) {
		ObjectMapper objectMapper = new ObjectMapper();
		
		try {
			byte[] data = objectMapper.writeValueAsBytes(src);
			return objectMapper.readValue(data, new TypeReference<LinkedHashMap<String, Object>>() {});
		} catch (IOException e) {
		}
		// not happened
		return null;
	}

}
