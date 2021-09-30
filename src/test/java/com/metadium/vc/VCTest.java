package com.metadium.vc;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.net.URI;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
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
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.StandardCharset;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

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
		assertNull(vc.getExpriationDate());
		assertEquals("did:meta:0x11111111120", ((Map<String, String>)vc.getCredentialSubject()).get("id"));
		assertEquals("mansud", ((Map<String, String>)vc.getCredentialSubject()).get("name"));
		
		vc.setExpirationDate(expire.getTime());
		assertEquals(expire.getTime().getTime()/1000*1000, vc.getExpriationDate().getTime());

		
		System.out.println("vctest vc");
		System.out.println(vc.toJSONString());
		
		try {
			//	Sign VC with ES256k (secp256k1).  keyID, nonce, private key
			SignedJWT signedJwt = vc.sign("did:meta:000003489384932859420#KeyManagement#73875892475", "0d8mf03", new ECDSASigner(privateKey));
			String token = signedJwt.serialize();
			System.out.println("vctest vc JWTs");
			System.out.println(token);
			
			// verify SignedVC
			SignedJWT signedJWT = SignedJWT.parse(token);
			assertTrue(signedJWT.verify(new ECDSAVerifier(publicKey)));
			VerifiableCredential verifiedVc = new VerifiableCredential(signedJWT);
			
			// test
			assertNotNull(verifiedVc);
			assertEquals(vc.getId(), verifiedVc.getId());
			assertTrue(verifiedVc.getTypes().contains("NameCredential"));
			assertEquals(vc.getIssuer(), verifiedVc.getIssuer());
			assertEquals(vc.getIssunaceDate(), verifiedVc.getIssunaceDate());
			assertEquals(vc.getExpriationDate(),  verifiedVc.getExpriationDate());
			assertEquals(vc.getCredentialSubject(), verifiedVc.getCredentialSubject());

			System.out.println("vctest verified vc");
			System.out.println(verifiedVc.toJSONString());
		} catch (JOSEException e) {
			e.printStackTrace();
		} catch (ParseException e) {
			e.printStackTrace();
		}
	}
	
	@SuppressWarnings("unchecked")
	@Test
	public void vctestIssuerObject() {
		Calendar issued = Calendar.getInstance();
		Calendar expire = Calendar.getInstance();
		expire.setTime(issued.getTime());
		expire.add(Calendar.DAY_OF_YEAR, 100);
		
		// Make Verifiable Credential
		VerifiableCredential vc = new VerifiableCredential();
		vc.setId(URI.create("http://aa.metadium.com/credential/343"));
		vc.addTypes(Collections.singletonList("NameCredential"));
		Map<String, String> issuerObject = new HashMap<String, String>();
		issuerObject.put("name", "Coinplug");
		vc.setIssuer(URI.create("did:meta:0x3489384932859420"), issuerObject);
		vc.setIssuanceDate(issued.getTime());
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
		assertEquals("Coinplug", vc.getIssuerObject().get("name"));
		assertEquals(issued.getTime().getTime()/1000*1000, vc.getIssunaceDate().getTime());
		assertNull(vc.getExpriationDate());
		assertEquals("did:meta:0x11111111120", ((Map<String, String>)vc.getCredentialSubject()).get("id"));
		assertEquals("mansud", ((Map<String, String>)vc.getCredentialSubject()).get("name"));
		
		vc.setExpirationDate(expire.getTime());
		assertEquals(expire.getTime().getTime()/1000*1000, vc.getExpriationDate().getTime());

		
		System.out.println("vctest vc");
		System.out.println(vc.toJSONString());
		
		try {
			//	Sign VC with ES256k (secp256k1).  keyID, nonce, private key
			SignedJWT signedJWT = vc.sign("did:meta:000003489384932859420#KeyManagement#73875892475", "0d8mf03", new ECDSASigner(privateKey)); 
			String token = signedJWT.serialize();
			System.out.println("vctest vc JWTs");
			System.out.println(token);
			
			// verify SignedVC
			assertTrue(signedJWT.verify(new ECDSAVerifier(publicKey)));
			VerifiableCredential verifiedVc = new VerifiableCredential(signedJWT);

			System.out.println("vctest verified vc");
			System.out.println(verifiedVc.toJSONString());

			// test
			assertNotNull(verifiedVc);
			assertEquals(vc.getId(), verifiedVc.getId());
			assertTrue(verifiedVc.getTypes().contains("NameCredential"));
			assertEquals(vc.getIssuer(), verifiedVc.getIssuer());
			assertEquals(vc.getIssuerObject().get("name"), verifiedVc.getIssuerObject().get("name"));
			assertEquals(vc.getIssunaceDate(), verifiedVc.getIssunaceDate());
			assertEquals(vc.getExpriationDate(),  verifiedVc.getExpriationDate());
			assertEquals(vc.getCredentialSubject(), verifiedVc.getCredentialSubject());

		} catch (JOSEException e) {
			e.printStackTrace();
		} catch (ParseException e) {
			e.printStackTrace();
		}
	}
	
	@Test
	public void vptest() throws InvalidAlgorithmParameterException {
		// test signed verifiable credential and public key
		final String vc1 = "eyJraWQiOiJkaWQ6bWV0YTowMDAwMDM0ODkzODQ5MzI4NTk0MjAjS2V5TWFuYWdlbWVudCM3Mzg3NTg5MjQ3NSIsInR5cCI6IkpXVCIsImFsZyI6IkVTMjU2SyJ9.eyJzdWIiOiJkaWQ6bWV0YToweDExMTExMTExMTIwIiwiaXNzIjoiZGlkOm1ldGE6MHgzNDg5Mzg0OTMyODU5NDIwIiwiZXhwIjoxNTc0OTMwNzM2LCJpYXQiOjE1NjYyOTA3MzYsIm5vbmNlIjoiMGQ4bWYwMyIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOlwvXC93M2lkLm9yZ1wvY3JlZGVudGlhbHNcL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJOYW1lQ3JlZGVudGlhbCJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJuYW1lIjoibWFuc3VkIn19LCJqdGkiOiJodHRwOlwvXC9hYS5tZXRhZGl1bS5jb21cL2NyZWRlbnRpYWxcLzM0MyJ9.xvS2sZMuIrIgH7FmCaUfnNuWxTyoXxRTLZpv6MSKh5LEPUx3_tFva9UmgbkCljC7-RZ1ccURz_F2_xc7QpkuFg";
		final String vc2 = "eyJraWQiOiJkaWQ6bWV0YTowMDAwMDM0ODkzODQ5MzI4NTk0MjAjS2V5TWFuYWdlbWVudCM3Mzg3NTg5MjQ3NSIsInR5cCI6IkpXVCIsImFsZyI6IkVTMjU2SyJ9.eyJzdWIiOiJkaWQ6bWV0YToweDExMTExMTExMTIwIiwiaXNzIjoiZGlkOm1ldGE6MHgzNDg5Mzg0OTMyODU5NDIwIiwiZXhwIjoxNTc0OTMwNzU3LCJpYXQiOjE1NjYyOTA3NTcsIm5vbmNlIjoiMGQ4bWYwMyIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOlwvXC93M2lkLm9yZ1wvY3JlZGVudGlhbHNcL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJOYW1lQ3JlZGVudGlhbCJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJuYW1lIjoibWFuc3VkIn19LCJqdGkiOiJodHRwOlwvXC9hYS5tZXRhZGl1bS5jb21cL2NyZWRlbnRpYWxcLzM0MyJ9.JklSXM2BoOnd93twpyXJnfJYRb8VmMSQL5kd5cCKDVuf1v3mScNyD0EXngnF_zQOWeV2-KewTpPyDWrhqRl1Lw";
		final BCECPublicKey vc1PublicKey = ECKeyUtils.toECPublicKey(Hex.decode("0498b6ba68b1aff37640a1cb119846d7a2554d50f9ebcd28d9f594075ac09936a90c5f8fca89b49bca93de945f2c4d572bd185d6d46592a445cc1ad5c5b009211b"), "secp256k1");
		final BCECPublicKey vc2PublicKey = ECKeyUtils.toECPublicKey(Hex.decode("042dd6ef966d395c0e92b376ffa98139662c9dc0a0fa7c9ca294248454aa3781d789f4bc5173fef351735cb90737d0d74a7fed93648177684a67a8a7f48f9a7b9d"), "secp256k1");
		
		KeyPairGeneratorSpi.EC ec = new KeyPairGeneratorSpi.EC();
		ec.initialize(new ECGenParameterSpec("secp256k1"), new SecureRandom());
		KeyPair keyPair = ec.generateKeyPair();
		
		BCECPrivateKey priKey = (BCECPrivateKey)keyPair.getPrivate();
		BCECPublicKey pubKey = (BCECPublicKey)keyPair.getPublic();
		
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
			Calendar cal = Calendar.getInstance();
			cal.add(Calendar.SECOND, 15);
			Date issueDate = new Date();
			JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
					.notBeforeTime(issueDate)
					.expirationTime(cal.getTime())
					.audience(Arrays.asList("test"))
					.build();
			SignedJWT vpObject = vp.sign("did:meta:0x3489384932859420#ManagementKey#4382758295", "0d8mf03", new ECDSASigner(priKey), claimsSet);
			String vpToken = vpObject.serialize();
			
			System.out.println("test publickey : "+ Hex.toHexString(ECKeyUtils.encodePublicKey(pubKey)));
			System.out.println("vptest vp JWTs");
			System.out.println(vpToken);
			
			// Verify verifiable presentation
			assertTrue(vpObject.verify(new ECDSAVerifier(pubKey)));
			assertEquals(cal.getTime().getTime()/1000*1000, vpObject.getJWTClaimsSet().getExpirationTime().getTime());
			assertEquals(issueDate.getTime()/1000*1000, vpObject.getJWTClaimsSet().getNotBeforeTime().getTime());
			VerifiablePresentation verifiedVp = new VerifiablePresentation(vpObject);
			
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
				SignedJWT vcJwt = SignedJWT.parse(vcToken);
				VerifiableCredential verifiedVc;

				if (vcToken.equals(vc1)) {
					assertTrue(vcJwt.verify(new ECDSAVerifier(vc1PublicKey)));
					verifiedVc = new VerifiableCredential(vcJwt);
				}
				else if (vcToken.equals(vc2)) {
					assertTrue(vcJwt.verify(new ECDSAVerifier(vc2PublicKey)));
					verifiedVc = new VerifiableCredential(vcJwt);
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
	
	@Test
	public void swiftSignVerify() throws ParseException, JOSEException {
		final BCECPublicKey publicKey = ECKeyUtils.toECPublicKey(Hex.decode("04203da4217f9afdf10dce3fb6deca70ccee9fb06754b4fcc8d93ad1dd13115c7f43d1c6438befe67d51d7bec0665cdffe02bbbd2f351081757e7b92dcd948dc99"), "secp256k1");
		String vp = "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6bWV0YTo0Mzg5NDgzNSJ9.eyJqdGkiOiJodHRwOlwvXC9hYS5tZXRhZGl1bS5jb21cL3ByZXNcL2ZmZiIsIm5vbmNlIjoidnAgbm9uY2UiLCJ2cCI6eyJ0eXBlIjpbIlZlcmlmaWFibGVQcmVzZW50YXRpb24iLCJOYW1lUHJlc2VudGF0aW9uIl0sIkBjb250ZXh0IjpbImh0dHA6XC9cL3czaWQub3JnXC9jcmVkZW50aWFsc1wvdjEiXSwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOlsiZXlKaGJHY2lPaUpGVXpJMU5rc2lMQ0pyYVdRaU9pSmthV1E2YldWMFlUb3pPRGM0TXpRalRXRnVZV2RsYldWdWRFdGxlU000T1RNME9UTTBPQ0o5LmV5SnBZWFFpT2pFMU5qVTVOREUxTURRc0ltcDBhU0k2SW1oMGRIQTZYQzljTDJGaExtMWxkR0ZrYVhWdExtTnZiVnd2WTNKbFpHVnVkR2xoYkZ3dk16UXpJaXdpZG1NaU9uc2lZM0psWkdWdWRHbGhiRk4xWW1wbFkzUWlPbnNpYm1GdFpTSTZJbTFoYm5OMVpDSjlMQ0pBWTI5dWRHVjRkQ0k2V3lKb2RIUndPbHd2WEM5M00ybGtMbTl5WjF3dlkzSmxaR1Z1ZEdsaGJITmNMM1l4SWwwc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0pPWVcxbFEzSmxaR1Z1ZEdsaGJDSmRmU3dpYm05dVkyVWlPaUp1YjI1alpTSXNJbVY0Y0NJNk1UVTJPRFV6TXpVd05Dd2ljM1ZpSWpvaVpHbGtPbTFsZEdFNk16Z3lOVGM0TXpJMU56RXhNVEV4TVRFeE1URXhNVEV4TVRFeE1URXhNVEV4TVNJc0ltbHpjeUk2SW1ScFpEcHRaWFJoT2pNME9Ea3pPRFUxTkRNeE1qUTFNVE15TlRRek1qVXlNelUwTXpJaWZRLmRtK3NvU2FcLzhja3pVdXFrVzhmaWVtdGIzZjJHYUd1VW5NaTB0Y3FyQjFaV3haSWtiZEtDMWUrOEEyZnNONjJlaFpmQ2hraXdLVEV2Y2pKNTNIcTZRdyIsImV5SmhiR2NpT2lKRlV6STFOa3NpTENKcmFXUWlPaUprYVdRNmJXVjBZVG96T0RjNE16UWpUV0Z1WVdkbGJXVnVkRXRsZVNNNE9UTTBPVE0wT0NKOS5leUpwWVhRaU9qRTFOalU1TkRFMU1EUXNJbXAwYVNJNkltaDBkSEE2WEM5Y0wyRmhMbTFsZEdGa2FYVnRMbU52YlZ3dlkzSmxaR1Z1ZEdsaGJGd3ZNelF6SWl3aWRtTWlPbnNpWTNKbFpHVnVkR2xoYkZOMVltcGxZM1FpT25zaWJtRnRaU0k2SW0xaGJuTjFaQ0o5TENKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3T2x3dlhDOTNNMmxrTG05eVoxd3ZZM0psWkdWdWRHbGhiSE5jTDNZeElsMHNJblI1Y0dVaU9sc2lWbVZ5YVdacFlXSnNaVU55WldSbGJuUnBZV3dpTENKT1lXMWxRM0psWkdWdWRHbGhiQ0pkZlN3aWJtOXVZMlVpT2lKdWIyNWpaU0lzSW1WNGNDSTZNVFUyT0RVek16VXdOQ3dpYzNWaUlqb2laR2xrT20xbGRHRTZNemd5TlRjNE16STFOekV4TVRFeE1URXhNVEV4TVRFeE1URXhNVEV4TVRFeE1TSXNJbWx6Y3lJNkltUnBaRHB0WlhSaE9qTTBPRGt6T0RVMU5ETXhNalExTVRNeU5UUXpNalV5TXpVME16SWlmUS5kbStzb1NhXC84Y2t6VXVxa1c4ZmllbXRiM2YyR2FHdVVuTWkwdGNxckIxWld4WklrYmRLQzFlKzhBMmZzTjYyZWhaZkNoa2l3S1RFdmNqSjUzSHE2UXciXX0sImlzcyI6ImRpZDptZXRhOjM4OTM0ODkyNDMxMjQ1NDIzNTIzNDU0MzI1NDIzIn0.uQ77WqGiRZECGOncRII/cf1wOT0a2/eTKpc/NHq+q/kksQB+TfICnY2SQmDAYrY1slLfwHRgfWGDH2j0jx+1+g";
		
		SignedJWT signedVp = SignedJWT.parse(vp);
		assertTrue(signedVp.verify(new ECDSAVerifier(publicKey)));
		VerifiablePresentation verifiedVP = new VerifiablePresentation(signedVp);
		assertNotNull(verifiedVP);
		if (verifiedVP != null) {
			for (Object c : verifiedVP.getVerifiableCredentials()) {
				SignedJWT signedVc = SignedJWT.parse((String)c);
				assertTrue(signedVc.verify(new ECDSAVerifier(publicKey)));
				VerifiableCredential verifiedVC = new VerifiableCredential(signedVc);
				assertNotNull(verifiedVC);
			}
		}		
	}
	
	@Test
	public void signtest() throws Exception {
		String testMessage = "eyJraWQiOiJkaWQ6bWV0YToweDM0ODkzODQ5MzI4NTk0MjAjTWFuYWdlbWVudEtleSM0MzgyNzU4Mjk1IiwidHlwIjoiSldUIiwiYWxnIjoiRVMyNTZLIn0.eyJpc3MiOiJkaWQ6bWV0YToweDM0ODkzODQ5MzI4NTk0MjAiLCJ2cCI6eyJAY29udGV4dCI6WyJodHRwczpcL1wvdzNpZC5vcmdcL2NyZWRlbnRpYWxzXC92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVQcmVzZW50YXRpb24iLCJUZXN0UHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SnJhV1FpT2lKa2FXUTZiV1YwWVRvd2VETTBPRGt6T0RRNU16STROVGswTWpBamEyVjVNU0lzSW5SNWNDSTZJa3BYVkNJc0ltRnNaeUk2SWtWVE1qVTJTeUo5LmV5SnpkV0lpT2lKa2FXUTZiV1YwWVRvd2VERXhNVEV4TVRFeE1USXdJaXdpYVhOeklqb2laR2xrT20xbGRHRTZNSGd6TkRnNU16ZzBPVE15T0RVNU5ESXdJaXdpWlhod0lqb3hOVGN6Tnprd05EUXpMQ0pwWVhRaU9qRTFOalV4TlRBME5ETXNJbTV2Ym1ObElqb2lNR1E0YldZd015SXNJblpqSWpwN0lrQmpiMjUwWlhoMElqcGJJbWgwZEhCek9sd3ZYQzkzTTJsa0xtOXlaMXd2WTNKbFpHVnVkR2xoYkhOY0wzWXhJbDBzSW5SNWNHVWlPbHNpVm1WeWFXWnBZV0pzWlVOeVpXUmxiblJwWVd3aUxDSk9ZVzFsUTNKbFpHVnVkR2xoYkNKZExDSmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUp1WVcxbElqb2liV0Z1YzNWa0luMTlMQ0pxZEdraU9pSm9kSFJ3T2x3dlhDOWhZUzV0WlhSaFpHbDFiUzVqYjIxY0wyTnlaV1JsYm5ScFlXeGNMek0wTXlKOS5RM2FGNUl1OF81N213OWkxMkRpeVRNOUxBRmlGcWUxRmdYMzVLRHF4YWNJaUlZU1ZGalhuTk1ESndPYmdJMmV6Q014TUVNdEg4ZWVhektnVjRZNzFqZyIsImV5SnJhV1FpT2lKa2FXUTZiV1YwWVRvd2VETTBPRGt6T0RRNU16STROVGswTWpBamEyVjVNU0lzSW5SNWNDSTZJa3BYVkNJc0ltRnNaeUk2SWtWVE1qVTJTeUo5LmV5SnpkV0lpT2lKa2FXUTZiV1YwWVRvd2VERXhNVEV4TVRFeE1USXdJaXdpYVhOeklqb2laR2xrT20xbGRHRTZNSGd6TkRnNU16ZzBPVE15T0RVNU5ESXdJaXdpWlhod0lqb3hOVGN6Tnprd05USTFMQ0pwWVhRaU9qRTFOalV4TlRBMU1qVXNJbTV2Ym1ObElqb2lNR1E0YldZd015SXNJblpqSWpwN0lrQmpiMjUwWlhoMElqcGJJbWgwZEhCek9sd3ZYQzkzTTJsa0xtOXlaMXd2WTNKbFpHVnVkR2xoYkhOY0wzWXhJbDBzSW5SNWNHVWlPbHNpVm1WeWFXWnBZV0pzWlVOeVpXUmxiblJwWVd3aUxDSk9ZVzFsUTNKbFpHVnVkR2xoYkNKZExDSmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUp1WVcxbElqb2liV0Z1YzNWa0luMTlMQ0pxZEdraU9pSm9kSFJ3T2x3dlhDOWhZUzV0WlhSaFpHbDFiUzVqYjIxY0wyTnlaV1JsYm5ScFlXeGNMek0wTXlKOS4yZHFoc0M5cl9XUVRYTW1UamM5N0dsT2Zyc0RDNk81LUtGSTA2dEFac2FHQUdsQ3c4bjRCb0NURlRpYzFsM2VSNEFHd0RvNGpkZ2s2UlVqbDZLSW9LQSJdfSwibm9uY2UiOiIwZDhtZjAzIiwianRpIjoiaHR0cDpcL1wvYWEubWV0YWRpdW0uY29tXC9wcmVzZW50YXRpb25cLzM0MyJ9";
		byte[] data = testMessage.getBytes(StandardCharset.UTF_8);
		System.out.println("data : "+testMessage);

		System.out.println("Test PublicKey : "+Hex.toHexString(ECKeyUtils.encodePublicKey(publicKey)));
		JWSHeader header = new JWSHeader(JWSAlgorithm.ES256K);
		ECDSASigner signer = new ECDSASigner(privateKey);
		Base64URL signature = signer.sign(header, data);
		System.out.println("signtest "+signature.toString());
	}
}
