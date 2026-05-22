/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.knox.gateway.util;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.apache.commons.codec.binary.Base64;
import org.apache.knox.gateway.i18n.GatewayUtilCommonMessages;
import org.apache.knox.gateway.i18n.messages.MessagesFactory;

public class X509CertificateUtil {

  private static GatewayUtilCommonMessages LOG = MessagesFactory.get(GatewayUtilCommonMessages.class);

  /**
   * Create a self-signed X.509 Certificate
   * @param dn the X.509 Distinguished Name, eg "CN=Test, L=London, C=GB"
   * @param pair the KeyPair
   * @param days how many days from now the Certificate is valid for
   * @param algorithm the signing algorithm, eg "SHA1withRSA"
   * @return self-signed X.509 certificate
   */
  public static X509Certificate generateCertificate(String dn, KeyPair pair, int days, String algorithm) {
    PrivateKey privkey = pair.getPrivate();
    Object x509CertImplObject = null;
    try {
      Date from = new Date();
      Date to = new Date(from.getTime() + days * 86400000L);

      Class<?> certInfoClass = Class.forName(getX509CertInfoModuleName());
      Constructor<?> certInfoConstr = certInfoClass.getConstructor();
      Object certInfoObject = certInfoConstr.newInstance();

      // Java 21 removed CertAttrSet and its set(String, Object)/get(String) methods.
      // Detect availability to support both Java 17 (uses set/get) and Java 21+ (uses field assignment).
      boolean hasCertAttrSetMethods = hasCertAttrSetApi(certInfoClass);

      // CertificateValidity interval = new CertificateValidity(from, to);
      Class<?> certValidityClass = Class.forName(getX509CertifValidityModuleName());
      Constructor<?> certValidityConstr = certValidityClass.getConstructor(Date.class, Date.class);
      Object certValidityObject = certValidityConstr.newInstance(from, to);

      BigInteger sn = new BigInteger(64, new SecureRandom());

      // X500Name owner = new X500Name(dn);
      Class<?> x500NameClass = Class.forName(getX509X500NameModuleName());
      Constructor<?> x500NameConstr = x500NameClass.getConstructor(String.class);
      Object x500NameObject = x500NameConstr.newInstance(dn);

      // CertificateSerialNumber
      Class<?> certificateSerialNumberClass = Class.forName(getCertificateSerialNumberModuleName());
      Constructor<?> certificateSerialNumberConstr = certificateSerialNumberClass
                                                         .getConstructor(BigInteger.class);
      Object certificateSerialNumberObject = certificateSerialNumberConstr.newInstance(sn);

      // CertificateX509Key
      Class<?> certificateX509KeyClass = Class.forName(getCertificateX509KeyModuleName());
      Constructor<?> certificateX509KeyConstr = certificateX509KeyClass
                                                    .getConstructor(PublicKey.class);
      Object certificateX509KeyObject = certificateX509KeyConstr.newInstance(pair.getPublic());

      // CertificateVersion(V3)
      Class<?> certificateVersionClass = Class.forName(getCertificateVersionModuleName());
      Constructor<?> certificateVersionConstr = certificateVersionClass.getConstructor(int.class);
      Constructor<?> certificateVersionConstr0 = certificateVersionClass.getConstructor();
      Object certVersionDefault = certificateVersionConstr0.newInstance();
      Field v3IntField = certVersionDefault.getClass().getDeclaredField("V3");
      v3IntField.setAccessible(true);
      int fValue = v3IntField.getInt(certVersionDefault);
      Object certificateVersionObject = certificateVersionConstr.newInstance(fValue);

      // AlgorithmId algo = new AlgorithmId(AlgorithmId.RSAEncryption_oid);
      Class<?> algorithmIdClass = Class.forName(getAlgorithmIdModuleName());
      Field rsaOidField = algorithmIdClass.getDeclaredField("RSAEncryption_oid");
      rsaOidField.setAccessible(true);
      Class<?> objectIdentifierClass = Class.forName(getObjectIdentifierModuleName());
      Object rsaOidValue = rsaOidField.get(algorithmIdClass);
      Constructor<?> algorithmIdConstr = algorithmIdClass.getConstructor(objectIdentifierClass);
      Object algorithmIdObject = algorithmIdConstr.newInstance(rsaOidValue);

      // CertificateAlgorithmId
      Class<?> certificateAlgorithmIdClass = Class.forName(getCertificateAlgorithmIdModuleName());
      Constructor<?> certificateAlgorithmIdConstr = certificateAlgorithmIdClass
                                                        .getConstructor(algorithmIdClass);
      Object certificateAlgorithmIdObject = certificateAlgorithmIdConstr
                                                .newInstance(algorithmIdObject);

      if (hasCertAttrSetMethods) {
        // Java 17 path: use set(String, Object) method from CertAttrSet
        Method methodSET = certInfoObject.getClass().getMethod("set", String.class, Object.class);

        methodSET.invoke(certInfoObject, getSetField(certInfoObject, "VALIDITY"), certValidityObject);
        methodSET.invoke(certInfoObject, getSetField(certInfoObject, "SERIAL_NUMBER"),
            certificateSerialNumberObject);

        try {
          Class<?> certificateSubjectNameClass = Class.forName(getCertificateSubjectNameModuleName());
          Constructor<?> certificateSubjectNameConstr = certificateSubjectNameClass
                                                            .getConstructor(x500NameClass);
          Object certificateSubjectNameObject = certificateSubjectNameConstr
                                                    .newInstance(x500NameObject);
          methodSET.invoke(certInfoObject, getSetField(certInfoObject, "SUBJECT"),
              certificateSubjectNameObject);
        } catch (InvocationTargetException | ClassNotFoundException e) {
          methodSET.invoke(certInfoObject, getSetField(certInfoObject, "SUBJECT"),
              x500NameObject);
        }

        try {
          Class<?> certificateIssuerNameClass = Class.forName(getCertificateIssuerNameModuleName());
          Constructor<?> certificateIssuerNameConstr = certificateIssuerNameClass
                                                           .getConstructor(x500NameClass);
          Object certificateIssuerNameObject = certificateIssuerNameConstr.newInstance(x500NameObject);
          methodSET.invoke(certInfoObject, getSetField(certInfoObject, "ISSUER"),
              certificateIssuerNameObject);
        } catch (InvocationTargetException | ClassNotFoundException e) {
          methodSET.invoke(certInfoObject, getSetField(certInfoObject, "ISSUER"),
              x500NameObject);
        }

        methodSET.invoke(certInfoObject, getSetField(certInfoObject, "KEY"),
            certificateX509KeyObject);
        methodSET.invoke(certInfoObject, getSetField(certInfoObject, "VERSION"),
            certificateVersionObject);
        methodSET.invoke(certInfoObject, getSetField(certInfoObject, "ALGORITHM_ID"),
            certificateAlgorithmIdObject);
      } else {
        // Java 21+ path: CertAttrSet was removed; assign protected fields directly
        setDeclaredField(certInfoObject, "interval", certValidityObject);
        setDeclaredField(certInfoObject, "serialNum", certificateSerialNumberObject);
        setDeclaredField(certInfoObject, "subject", x500NameObject);
        setDeclaredField(certInfoObject, "issuer", x500NameObject);
        setDeclaredField(certInfoObject, "pubKey", certificateX509KeyObject);
        setDeclaredField(certInfoObject, "version", certificateVersionObject);
        setDeclaredField(certInfoObject, "algId", certificateAlgorithmIdObject);
      }

      // Set the SAN extension
      Class<?> generalNameInterfaceClass = Class.forName(getGeneralNameInterfaceModuleName());

      Class<?> generalNameClass = Class.forName(getGeneralNameModuleName());
      Constructor<?> generalNameConstr = generalNameClass.getConstructor(generalNameInterfaceClass);

      // GeneralNames generalNames = new GeneralNames();
      Class<?> generalNamesClass = Class.forName(getGeneralNamesModuleName());
      Constructor<?> generalNamesConstr = generalNamesClass.getConstructor();
      Object generalNamesObject = generalNamesConstr.newInstance();
      Method generalNamesAdd = generalNamesObject.getClass().getMethod("add", generalNameClass);

      Class<?> dnsNameClass = Class.forName(getDNSNameModuleName());
      Constructor<?> dnsNameConstr = dnsNameClass.getConstructor(String.class);

      boolean generalNameAdded = false;
      // Pull the hostname out of the DN
      String hostname = dn.split(",", 2)[0].split("=", 2)[1];
      if("localhost".equals(hostname)) {
        // Add short hostname
        String detectedHostname = InetAddress.getLocalHost().getHostName();
        if (Character.isAlphabetic(detectedHostname.charAt(0))) {
          Object dnsNameObject = dnsNameConstr.newInstance(detectedHostname);
          Object generalNameObject = generalNameConstr.newInstance(dnsNameObject);
          generalNamesAdd.invoke(generalNamesObject, generalNameObject);
          generalNameAdded = true;
        }

        // Add fully qualified hostname
        String detectedFullyQualifiedHostname = InetAddress.getLocalHost().getCanonicalHostName();
        if (Character.isAlphabetic(detectedFullyQualifiedHostname.charAt(0))) {
          Object fullyQualifiedDnsNameObject = dnsNameConstr.newInstance(detectedFullyQualifiedHostname);
          Object fullyQualifiedGeneralNameObject = generalNameConstr.newInstance(fullyQualifiedDnsNameObject);
          generalNamesAdd.invoke(generalNamesObject, fullyQualifiedGeneralNameObject);
          generalNameAdded = true;
        }
      }

      if (Character.isAlphabetic(hostname.charAt(0))) {
        Object dnsNameObject = dnsNameConstr.newInstance(hostname);
        Object generalNameObject = generalNameConstr.newInstance(dnsNameObject);
        generalNamesAdd.invoke(generalNamesObject, generalNameObject);
        generalNameAdded = true;
      }

      if (generalNameAdded) {
        Class<?> subjectAlternativeNameExtensionClass = Class.forName(getSubjectAlternativeNameExtensionModuleName());
        Constructor<?> subjectAlternativeNameExtensionConstr = subjectAlternativeNameExtensionClass.getConstructor(generalNamesClass);
        Object subjectAlternativeNameExtensionObject = subjectAlternativeNameExtensionConstr.newInstance(generalNamesObject);

        Class<?> certificateExtensionsClass = Class.forName(getCertificateExtensionsModuleName());
        Constructor<?> certificateExtensionsConstr = certificateExtensionsClass.getConstructor();
        Object certificateExtensionsObject = certificateExtensionsConstr.newInstance();

        Method getExtensionIdMethod = subjectAlternativeNameExtensionObject.getClass().getMethod("getExtensionId");
        String sanExtensionId = getExtensionIdMethod.invoke(subjectAlternativeNameExtensionObject).toString();

        if (hasCertAttrSetMethods) {
          Method methodSET = certInfoObject.getClass().getMethod("set", String.class, Object.class);
          Method certificateExtensionsSet = certificateExtensionsObject.getClass().getMethod("set", String.class, Object.class);
          certificateExtensionsSet.invoke(certificateExtensionsObject, sanExtensionId, subjectAlternativeNameExtensionObject);
          methodSET.invoke(certInfoObject, getSetField(certInfoObject, "EXTENSIONS"), certificateExtensionsObject);
        } else {
          // Java 21+: CertificateExtensions uses setExtension(String, Extension)
          Class<?> extensionClass = Class.forName(getExtensionModuleName());
          Method setExtMethod = certificateExtensionsObject.getClass().getMethod("setExtension", String.class, extensionClass);
          setExtMethod.invoke(certificateExtensionsObject, sanExtensionId, subjectAlternativeNameExtensionObject);
          setDeclaredField(certInfoObject, "extensions", certificateExtensionsObject);
        }
      }

      // Sign the cert to identify the algorithm that's used.
      Class<?> x509CertImplClass = Class.forName(getX509CertImplModuleName());
      Constructor<?> x509CertImplConstr = x509CertImplClass.getConstructor(certInfoClass);
      x509CertImplObject = x509CertImplConstr.newInstance(certInfoObject);

      Method signMethod = x509CertImplObject.getClass().getMethod("sign",
          PrivateKey.class, String.class);
      signMethod.invoke(x509CertImplObject, privkey, algorithm);

      // Update the algorithm from the signed cert, and resign.
      if (hasCertAttrSetMethods) {
        Method methodSET = certInfoObject.getClass().getMethod("set", String.class, Object.class);
        Method methoGET = x509CertImplObject.getClass().getMethod("get", String.class);
        String sig_alg = getSetField(x509CertImplObject, "SIG_ALG");
        String certAlgoIdNameValue = getSetField(certificateAlgorithmIdObject, "NAME");
        String certAlgoIdAlgoValue = getSetField(certificateAlgorithmIdObject, "ALGORITHM");
        methodSET.invoke(certInfoObject, certAlgoIdNameValue + "." + certAlgoIdAlgoValue,
            methoGET.invoke(x509CertImplObject, sig_alg));
      } else {
        // Java 21+: read algId field from X509CertImpl, wrap in CertificateAlgorithmId, set on info
        Field implAlgIdField = x509CertImplObject.getClass().getDeclaredField("algId");
        implAlgIdField.setAccessible(true);
        Object signedAlgId = implAlgIdField.get(x509CertImplObject);
        Object newCertAlgId = certificateAlgorithmIdConstr.newInstance(signedAlgId);
        setDeclaredField(certInfoObject, "algId", newCertAlgId);
      }

      // Recreate cert with updated info and resign
      x509CertImplObject = x509CertImplConstr.newInstance(certInfoObject);
      signMethod.invoke(x509CertImplObject, privkey, algorithm);
    } catch (Exception e) {
      LOG.failedToGenerateCertificate(e);
    }
    return (X509Certificate) x509CertImplObject;
  }

  private static boolean hasCertAttrSetApi(Class<?> certInfoClass) {
    try {
      certInfoClass.getMethod("set", String.class, Object.class);
      return true;
    } catch (NoSuchMethodException e) {
      return false;
    }
  }

  private static void setDeclaredField(Object obj, String fieldName, Object value) throws Exception {
    Field field = obj.getClass().getDeclaredField(fieldName);
    field.setAccessible(true);
    field.set(obj, value);
  }

  private static String getX509CertInfoModuleName() {
    return System.getProperty("java.vendor").contains("IBM") ? "com.ibm.security.x509.X509CertInfo"
               : "sun.security.x509.X509CertInfo";
  }

  private static String getX509CertifValidityModuleName() {
    return System.getProperty("java.vendor").contains("IBM") ?
               "com.ibm.security.x509.CertificateValidity" :
               "sun.security.x509.CertificateValidity";
  }

  private static String getX509X500NameModuleName() {
    return System.getProperty("java.vendor").contains("IBM") ?
               "com.ibm.security.x509.X500Name" :
               "sun.security.x509.X500Name";
  }

  private static String getCertificateSerialNumberModuleName() {
    return System.getProperty("java.vendor").contains("IBM") ?
               "com.ibm.security.x509.CertificateSerialNumber" :
               "sun.security.x509.CertificateSerialNumber";
  }

  private static String getCertificateSubjectNameModuleName() {
    return System.getProperty("java.vendor").contains("IBM") ?
               "com.ibm.security.x509.CertificateSubjectName" :
               "sun.security.x509.CertificateSubjectName";
  }

  private static String getCertificateIssuerNameModuleName() {
    return System.getProperty("java.vendor").contains("IBM") ?
               "com.ibm.security.x509.CertificateIssuerName" :
               "sun.security.x509.CertificateIssuerName";
  }

  private static String getCertificateX509KeyModuleName() {
    return System.getProperty("java.vendor").contains("IBM") ?
               "com.ibm.security.x509.CertificateX509Key" :
               "sun.security.x509.CertificateX509Key";
  }

  private static String getCertificateVersionModuleName() {
    return System.getProperty("java.vendor").contains("IBM") ?
               "com.ibm.security.x509.CertificateVersion" :
               "sun.security.x509.CertificateVersion";
  }

  private static String getAlgorithmIdModuleName() {
    return System.getProperty("java.vendor").contains("IBM") ?
               "com.ibm.security.x509.AlgorithmId" :
               "sun.security.x509.AlgorithmId";
  }

  private static String getObjectIdentifierModuleName() {
    return System.getProperty("java.vendor").contains("IBM") ?
               "com.ibm.security.util.ObjectIdentifier" :
               "sun.security.util.ObjectIdentifier";
  }

  private static String getCertificateAlgorithmIdModuleName() {
    return System.getProperty("java.vendor").contains("IBM") ?
               "com.ibm.security.x509.CertificateAlgorithmId" :
               "sun.security.x509.CertificateAlgorithmId";
  }

  private static String getGeneralNameInterfaceModuleName() {
    return System.getProperty("java.vendor").contains("IBM") ?
               "com.ibm.security.x509.GeneralNameInterface" :// TODO
               "sun.security.x509.GeneralNameInterface";
  }

  private static String getGeneralNameModuleName() {
    return System.getProperty("java.vendor").contains("IBM") ?
               "com.ibm.security.x509.GeneralName" : // TODO
               "sun.security.x509.GeneralName";
  }

  private static String getGeneralNamesModuleName() {
    return System.getProperty("java.vendor").contains("IBM") ?
               "com.ibm.security.x509.GeneralNames" : // TODO
               "sun.security.x509.GeneralNames";
  }

  private static String getDNSNameModuleName() {
    return System.getProperty("java.vendor").contains("IBM") ?
               "com.ibm.security.x509.DNSName" : // TODO
               "sun.security.x509.DNSName";
  }

  private static String getSubjectAlternativeNameExtensionModuleName() {
    return System.getProperty("java.vendor").contains("IBM") ?
               "com.ibm.security.x509.SubjectAlternativeNameExtension" : // TODO
               "sun.security.x509.SubjectAlternativeNameExtension";
  }

  private static String getCertificateExtensionsModuleName() {
    return System.getProperty("java.vendor").contains("IBM") ?
               "com.ibm.security.x509.CertificateExtensions" : // TODO
               "sun.security.x509.CertificateExtensions";
  }

  private static String getExtensionModuleName() {
    return System.getProperty("java.vendor").contains("IBM") ?
               "com.ibm.security.x509.Extension" :
               "sun.security.x509.Extension";
  }

  private static String getX509CertImplModuleName() {
    return System.getProperty("java.vendor").contains("IBM") ?
               "com.ibm.security.x509.X509CertImpl" :
               "sun.security.x509.X509CertImpl";
  }

  private static String getSetField(Object obj, String setString)
      throws Exception {
    Field privateStringField = obj.getClass().getDeclaredField(setString);
    privateStringField.setAccessible(true);
    return (String) privateStringField.get(obj);
  }

  public static void writeCertificateToFile(Certificate cert, final File file)
      throws CertificateEncodingException, IOException {
    byte[] bytes = cert.getEncoded();
    Base64 encoder = new Base64( 76, "\n".getBytes( StandardCharsets.US_ASCII ) );
    try(OutputStream out = Files.newOutputStream(file.toPath()) ) {
      out.write( "-----BEGIN CERTIFICATE-----\n".getBytes( StandardCharsets.US_ASCII ) );
      out.write( encoder.encodeToString( bytes ).getBytes( StandardCharsets.US_ASCII ) );
      out.write( "-----END CERTIFICATE-----\n".getBytes( StandardCharsets.US_ASCII ) );
    }
  }

  /*
   * Writes one certificate into the given keystore file protected by the default password
   */
  private static void writeCertificateToKeyStore(Certificate cert, final File file, String type)
      throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
    writeCertificateToKeyStore(cert, file, type, null);
  }

  /*
   * Writes one certificate into the given keystore file protected by the given password
   */
  private static void writeCertificateToKeyStore(Certificate cert, final File file, String type, String keystorePassword)
      throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
    writeCertificatesToKeyStore(new Certificate[] { cert }, file, type, keystorePassword);
  }

  /*
   * Writes an arbitrary number of certificates into the given keystore file protected by the given password
   */
  private static void writeCertificatesToKeyStore(Certificate[] certs, final File file, String type, String keystorePassword)
      throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
    if (certs != null) {
      KeyStore ks = KeyStore.getInstance(type);

      char[] password = keystorePassword == null ? "changeit".toCharArray() : keystorePassword.toCharArray();
      ks.load(null, password);
      int counter = 0;
      for (Certificate cert : certs) {
        ks.setCertificateEntry("gateway-identity" + (++counter), cert); //it really does not matter what we set as alias for the certificate
      }
      /* Coverity Scan CID 1361992 */
      try (OutputStream fos = Files.newOutputStream(file.toPath())) {
        ks.store(fos, password);
      }
    }
  }

  public static void writeCertificateToJks(Certificate cert, final File file)
      throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
    writeCertificateToKeyStore(cert, file, "jks");
  }

  public static void writeCertificateToJks(Certificate cert, final File file, String keystorePassword)
      throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
    writeCertificateToKeyStore(cert, file, "jks", keystorePassword);
  }

  public static void writeCertificatesToJks(Certificate[] certs, final File file, String keystorePassword)
      throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
    writeCertificatesToKeyStore(certs, file, "jks", keystorePassword);
  }

  public static void writeCertificateToJceks(Certificate cert, final File file)
      throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
    writeCertificateToKeyStore(cert, file, "jceks");
  }

  public static void writeCertificateToPkcs12(Certificate cert, final File file)
      throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
    writeCertificateToKeyStore(cert, file, "pkcs12");
  }

  /**
   * Tests the X509 certificate to see if it was self-signed.
   * <p>
   * The certificate is determined to be self-signed if the subject DN is the same as the issuer DN
   *
   * @param certificate the {@link X509Certificate} to test
   * @return <code>true</code> if the X509 certficate is self-signed; otherwise <code>false</code>
   */
  public static boolean isSelfSignedCertificate(Certificate certificate) {
    if (certificate instanceof X509Certificate) {
      X509Certificate x509Certificate = (X509Certificate) certificate;
      return x509Certificate.getSubjectX500Principal().equals(x509Certificate.getIssuerX500Principal());
    } else {
      return false;
    }
  }
}
