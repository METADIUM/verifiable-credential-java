package com.metadium.vc;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.net.URI;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.text.ParseException;
import java.util.Calendar;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;

import com.metadium.vc.util.ECKeyUtils;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;

public class VCTest {
	static BCECPrivateKey privateKey;
	static BCECPublicKey publicKey;
	
	@Before
	public void setup() throws InvalidAlgorithmParameterException {
		System.setOut(System.out);
		System.setErr(System.err);
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
		
		if (privateKey == null) {
			KeyPairGeneratorSpi.EC ec = new KeyPairGeneratorSpi.EC();
			ec.initialize(new ECGenParameterSpec("secp256k1"), new SecureRandom());
			KeyPair keyPair = ec.generateKeyPair();
			
			privateKey = (BCECPrivateKey)keyPair.getPrivate();
			publicKey = (BCECPublicKey)keyPair.getPublic();
			
			String testPublicKeyString = Hex.toHexString(ECKeyUtils.encodePublicKey(publicKey));
			System.out.println("Test PublicKey : "+testPublicKeyString);
		}
	}
	
	
	@SuppressWarnings("unchecked")
	@Test
	public void vctest() {
		Calendar issued = Calendar.getInstance();
		Calendar expire = Calendar.getInstance();
		expire.setTime(issued.getTime());
		expire.add(Calendar.DAY_OF_YEAR, 100);
		
		// Make Verifiable Credential
		VerifiableCredential vc = new VerifiableCredential();
		vc.setId(URI.create("http://aa.metadium.com/credential/343"));
		vc.addTypes(Collections.singletonList("NameCredential"));
		vc.setIssuer(URI.create("did:meta:0x3489384932859420"));
		vc.setIssuanceDate(issued.getTime());
		vc.setExpirationDate(expire.getTime());
		LinkedHashMap<String, String> subject = new LinkedHashMap<>();
		subject.put("id", "did:meta:0x11111111120");
		subject.put("name", "mansud");
		vc.setCredentialSubject(subject);
		
		// test
		assertTrue(vc.getContexts().contains(VerifiableCredential.JSONLD_CONTEXT_CREDENTIALS));
		assertEquals("http://aa.metadium.com/credential/343", vc.getId().toString());
		assertTrue(vc.getTypes().contains(VerifiableCredential.JSONLD_TYPE_CREDENTIAL));
		assertTrue(vc.getTypes().contains("NameCredential"));
		assertEquals("did:meta:0x3489384932859420", vc.getIssuer().toString());
		assertEquals(issued.getTime().getTime()/1000*1000, vc.getIssunaceDate().getTime());
		assertEquals(expire.getTime().getTime()/1000*1000, vc.getExpriationDate().getTime());
		assertEquals("did:meta:0x11111111120", ((Map<String, String>)vc.getCredentialSubject()).get("id"));
		assertEquals("mansud", ((Map<String, String>)vc.getCredentialSubject()).get("name"));
		
		System.out.println("vctest vc");
		System.out.println(vc.toJSONString());
		
		VerifiableJWTSignerAndVerifier signer = new VerifiableJWTSignerAndVerifier();
		try {
			//	Sign VC with ES256k (secp256k1).  keyID, nonce, private key
			JWSObject jwsObject = signer.sign(vc, JWSAlgorithm.ES256K, "did:meta:000003489384932859420#KeyManagement#73875892475", "0d8mf03", new ECDSASigner(privateKey));
			String token = jwsObject.serialize();
			System.out.println("vctest vc JWTs");
			System.out.println(token);
			
			// verify SignedVC
			VerifiableCredential verifiedVc = (VerifiableCredential)signer.verify(token, new ECDSAVerifier(publicKey));
			
			// test
			assertNotNull(verifiedVc);
			assertEquals(vc.getId(), verifiedVc.getId());
			assertTrue(verifiedVc.getTypes().contains("NameCredential"));
			assertEquals(vc.getIssuer(), verifiedVc.getIssuer());
			assertEquals(vc.getIssunaceDate(), verifiedVc.getIssunaceDate());
			assertEquals(vc.getCredentialSubject(), verifiedVc.getCredentialSubject());

			System.out.println("vctest verified vc");
			System.out.println(verifiedVc.toJSONString());

		} catch (JOSEException e) {
			e.printStackTrace();
		} catch (ParseException e) {
			e.printStackTrace();
		}
	}
	
	@Test
	public void vptest() {
		// test signed verifiable credential and public key
		final String vc1 = "eyJraWQiOiJkaWQ6bWV0YToweDM0ODkzODQ5MzI4NTk0MjAja2V5MSIsInR5cCI6IkpXVCIsImFsZyI6IkVTMjU2SyJ9.eyJzdWIiOiJkaWQ6bWV0YToweDExMTExMTExMTIwIiwiaXNzIjoiZGlkOm1ldGE6MHgzNDg5Mzg0OTMyODU5NDIwIiwiZXhwIjoxNTczNzkwNDQzLCJpYXQiOjE1NjUxNTA0NDMsIm5vbmNlIjoiMGQ4bWYwMyIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOlwvXC93M2lkLm9yZ1wvY3JlZGVudGlhbHNcL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJOYW1lQ3JlZGVudGlhbCJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJuYW1lIjoibWFuc3VkIn19LCJqdGkiOiJodHRwOlwvXC9hYS5tZXRhZGl1bS5jb21cL2NyZWRlbnRpYWxcLzM0MyJ9.Q3aF5Iu8_57mw9i12DiyTM9LAFiFqe1FgX35KDqxacIiIYSVFjXnNMDJwObgI2ezCMxMEMtH8eeazKgV4Y71jg";
		final String vc2 = "eyJraWQiOiJkaWQ6bWV0YToweDM0ODkzODQ5MzI4NTk0MjAja2V5MSIsInR5cCI6IkpXVCIsImFsZyI6IkVTMjU2SyJ9.eyJzdWIiOiJkaWQ6bWV0YToweDExMTExMTExMTIwIiwiaXNzIjoiZGlkOm1ldGE6MHgzNDg5Mzg0OTMyODU5NDIwIiwiZXhwIjoxNTczNzkwNTI1LCJpYXQiOjE1NjUxNTA1MjUsIm5vbmNlIjoiMGQ4bWYwMyIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOlwvXC93M2lkLm9yZ1wvY3JlZGVudGlhbHNcL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJOYW1lQ3JlZGVudGlhbCJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJuYW1lIjoibWFuc3VkIn19LCJqdGkiOiJodHRwOlwvXC9hYS5tZXRhZGl1bS5jb21cL2NyZWRlbnRpYWxcLzM0MyJ9.2dqhsC9r_WQTXMmTjc97GlOfrsDC6O5-KFI06tAZsaGAGlCw8n4BoCTFTic1l3eR4AGwDo4jdgk6RUjl6KIoKA";
		final BCECPublicKey vc1PublicKey = ECKeyUtils.toECPublicKey(Hex.decode("047da0aea4de409ed00d0dd87a0b266835739e303b942127aeb5243c78485019ff007416f986e4bd157a62590d7948b2f83f3b583a7835f9484b6e25c272c40bc0"), "secp256k1");
		final BCECPublicKey vc2PublicKey = ECKeyUtils.toECPublicKey(Hex.decode("047a446238da21d0a36b0aebfce56c7801afe24919ed80ec088bae48f4ba105a260555d052e09ac522e5e613e4361fe7a6ae9d417da6a60ed40cf3a5f1d0bed436"), "secp256k1");
		
		VerifiableJWTSignerAndVerifier signer = new VerifiableJWTSignerAndVerifier();
		try {
			// Create verifiable presentation
			VerifiablePresentation vp = new VerifiablePresentation();
			vp.setId(URI.create("http://aa.metadium.com/presentation/343"));
			vp.setHolder(URI.create("did:meta:0x3489384932859420"));
			vp.addTypes(Collections.singletonList("TestPresentation"));
			vp.addVerifiableCredential(vc1);
			vp.addVerifiableCredential(vc2);
			
			// test
			assertEquals("http://aa.metadium.com/presentation/343", vp.getId().toString());
			assertEquals("did:meta:0x3489384932859420", vp.getHolder().toString());
			assertTrue(vp.getTypes().contains(VerifiablePresentation.JSONLD_TYPE_PRESENTATION));
			assertTrue(vp.getTypes().contains("TestPresentation"));
			assertTrue(vp.getVerifiableCredentials().contains(vc1));
			assertTrue(vp.getVerifiableCredentials().contains(vc2));
			
			System.out.println("vptest vp ");
			System.out.println(vp.toJSONString());
			
			// Sign verifiable presentation with ES256k (secp256k1). keyID, nonce, private key
			JWSObject vpObject = signer.sign(vp, JWSAlgorithm.ES256K, "did:meta:0x3489384932859420#ManagementKey#4382758295", "0d8mf03", new ECDSASigner(privateKey));
			String vpToken = vpObject.serialize();
			
			System.out.println("vptest vp JWTs");
			System.out.println(vpToken);
			
			// Verify verifiable presentation
			VerifiablePresentation verifiedVp = (VerifiablePresentation)signer.verify(vpToken, new ECDSAVerifier(publicKey));
			
			// test
			assertNotNull(verifiedVp);
			assertEquals(vp.getId(), verifiedVp.getId());
			assertEquals(vp.getHolder(), verifiedVp.getHolder());
			assertArrayEquals(vp.getVerifiableCredentials().toArray(), verifiedVp.getVerifiableCredentials().toArray());
			assertArrayEquals(vp.getTypes().toArray(), verifiedVp.getTypes().toArray());
			
			System.out.println("vptest verified vp");
			System.out.println(verifiedVp.toJSONString());
			
			// verify verifiable credential
			for (Object vc : verifiedVp.getVerifiableCredentials()) {
				String vcToken = (String)vc;
				VerifiableCredential verifiedVc;
				
				if (vcToken.equals(vc1)) {
					verifiedVc = (VerifiableCredential)signer.verify((String)vc, new ECDSAVerifier(vc1PublicKey));
				}
				else if (vcToken.equals(vc2)) {
					verifiedVc = (VerifiableCredential)signer.verify((String)vc, new ECDSAVerifier(vc2PublicKey));
				}
				else {
					continue;
				}
				
				assertNotNull(verifiedVc);
				System.out.println("vptest verified vc");
				System.out.println(verifiedVc.toJSONString());
			}
		}
		catch (Exception e) {
		}
	}
}
