package controllers;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.mail.EmailException;
import org.apache.commons.mail.SimpleEmail;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import pdfbox.CMSProcessableInputStream;
import play.db.jpa.GenericModel;
import play.db.jpa.JPABase;
import play.libs.Mail;
import play.mvc.*;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.*;

import models.*;

import javax.security.auth.x500.X500Principal;

public class Application extends Controller {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void index() throws Exception {
        String email = Scope.Session.current().get("email");
        if (email != null) {
            if (email.equals("validador@contoso.com")) {
                List<JPABase> subscribers = Subscriber.findAll();
                // TODO list only the ones that aren't validated already
                render("Application/indexvalidator.html", subscribers);
            } else {
                Subscriber subscriber = getCurrentSubscriber();
                // Just a fix for the case when the user or database has been deleted during tests.
                if (subscriber == null) {
                    Scope.Session.current().clear();
                    login();
                }

                if (!subscriber.emailVerified) {
                    flash.put("warning", "El correo electrónico no ha sido verificado. <a href='"+Router.getFullUrl("Application.sendverificationemailagain")+"'>Enviar correo de verificación nuevamente</a>.");
                }
                render("Application/indexsubscriber.html", subscriber);
            }
        } else {
            login();
        }
    }

    public static void signaturestart() throws Exception {
        Subscriber currentSubscriber = getCurrentSubscriber();
        List<Object> pdfDocuments = PdfDocument.find("bySubscriber", currentSubscriber).fetch();
        render(pdfDocuments);
    }

    public static void validation(String email) {
        Subscriber subscriber = Subscriber.find("byEmail", email).first();
        render(subscriber);
    }

    public static void validationdownloaddni(String email) {
        Subscriber subscriber = Subscriber.find("byEmail", email).first();
        byte[] decode = b64Decode(subscriber.dniFile);
        String emailWithoutSpecialChars = simplifyEmail(subscriber);
        renderBinary(new java.io.ByteArrayInputStream(decode), emailWithoutSpecialChars + "_dni.pdf");

    }

    public static void downloadcertificate() {
        Subscriber currentSubscriber = getCurrentSubscriber();
        String certificatePem = currentSubscriber.certificatePem;
        String emailWithoutSpecialChars = simplifyEmail(currentSubscriber);
        renderBinary(new ByteArrayInputStream(certificatePem.getBytes()), emailWithoutSpecialChars + "_certificate.crt");
    }


    public static void downloadcacertificate() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream("conf/rootca.pfx"), "secret".toCharArray());
        String alias = keyStore.aliases().nextElement();
        X509Certificate rootCertificate = (X509Certificate) keyStore.getCertificate(alias);
        StringWriter writer = new StringWriter();
        PEMWriter pemWriter = new PEMWriter(writer);
        pemWriter.writeObject(rootCertificate);
        pemWriter.flush();
        renderBinary(new ByteArrayInputStream(writer.toString().getBytes()), "rootca.crt");
    }

    public static void validationdownloadficharuc(String email) {
        Subscriber subscriber = Subscriber.find("byEmail", email).first();
        byte[] decode = b64Decode(subscriber.fichaRucFile);
        String emailWithoutSpecialChars = simplifyEmail(subscriber);
        renderBinary(new java.io.ByteArrayInputStream(decode), emailWithoutSpecialChars + "_ficharuc.pdf");

    }

    public static void validationdownloadpoa(String email) {
        Subscriber subscriber = Subscriber.find("byEmail", email).first();
        byte[] decode = b64Decode(subscriber.powerOfAttorneyFile);
        String emailWithoutSpecialChars = simplifyEmail(subscriber);
        renderBinary(new java.io.ByteArrayInputStream(decode), emailWithoutSpecialChars + "_vigenciadepoder.pdf");

    }

    private static String simplifyEmail(Subscriber subscriber) {
        String emailWithoutSpecialChars = subscriber.email.replaceAll("[^a-zA-Z0-9]", "_");
        return emailWithoutSpecialChars;
    }

    private static byte[] b64Decode(String base64) {
        return Base64.getDecoder().decode(base64);
    }

    public static void validationconfirmation(String email) throws Exception {
        Subscriber subscriber = Subscriber.find("byEmail", email).first();
        subscriber.dniFileValidated = Boolean.parseBoolean(Http.Request.current().params.get("dni"));
        subscriber.fichaRucFileValidated = Boolean.parseBoolean(Http.Request.current().params.get("fichaRuc"));
        subscriber.powerOfAttorneyFileValidated = Boolean.parseBoolean(Http.Request.current().params.get("powerOfAttorney"));
        
        subscriber.validatedBy = "validador@contoso.com";
        subscriber.validatedAt = new Date();
        
        subscriber.save();
        String validatedDocuments = "";
        if (subscriber.dniFileValidated) {
            validatedDocuments += "DNI, ";
        }
        if (subscriber.fichaRucFileValidated) {
            validatedDocuments += "Ficha RUC, ";
        }
        if (subscriber.powerOfAttorneyFileValidated) {
            validatedDocuments += "Vigencia de poder";
        }
        flash.success("Se validó: " + validatedDocuments);
        
        sendEmail(subscriber.email, "IS283 - Aplicación de firma - Documentos validados", "Sus documentos fueron validados exitosamente.");
        validation(email);
    }

    public static Subscriber getCurrentSubscriber() {
        Subscriber subscriber = Subscriber.find("byEmail", Scope.Session.current().get("email")).first();
        return subscriber;
    }

    public static void registerstep1() {
        render();
    }

    public static void registerstep1submit(String emailAddress, String password, String passwordConfirmation) throws Exception {

        if (StringUtils.isBlank(emailAddress) || StringUtils.isBlank(password) || StringUtils.isBlank(passwordConfirmation)) {
            flash.error("Todos los campos son requeridos.");
            registerstep1();
        }
        
        GenericModel.JPAQuery byEmail = Subscriber.find("byEmail", emailAddress);
        List<Object> fetch = byEmail.fetch();
        if (fetch.size() > 0) {
            flash.error("La dirección de correo electrónico ya está registrada.");
        } else {

            if (!password.equals(passwordConfirmation)) {
                flash.error("Las contraseñas no coinciden.");
                registerstep1();
            }

            Subscriber subscriber = new Subscriber();
            subscriber.email = emailAddress;
            subscriber.password = password;
            // Generate verification code
            String code = UUID.randomUUID().toString();
            subscriber.emailVerificationCode = code;
            
            subscriber.save();

            sendVerificationEmail(emailAddress, code);
            flash.success("Registro inicial exitoso. A continuación recibirá un correo electrónico de verificación.");
        }

        registerstep1();
    }

    public static void sendverificationemailagain() throws Exception {
        Subscriber currentSubscriber = getCurrentSubscriber();
        sendVerificationEmail(currentSubscriber.email, currentSubscriber.emailVerificationCode);
        flash.success("Correo de verificación reenviado.");
        index();
    }


    private static void sendVerificationEmail(String emailAddress, String code) throws EmailException {
        String subject = "IS283 - Aplicación de firma - Verificación de correo electrónico";
        String fullUrl = Router.getFullUrl("Application.verify", new HashMap<>(Map.of("email", emailAddress, "code", code)));
        String body = "Por favor, haga clic en el siguiente enlace para verificar su dirección de correo electrónico: " + fullUrl;

        sendEmail(emailAddress, subject, body);
    }

    private static void sendEmail(String emailAddress, String subject, String body) throws EmailException {
        SimpleEmail email = new SimpleEmail();
        email.setFrom("jaime@blobfish.pe");
        email.addTo(emailAddress);
        email.setSubject(subject);
        email.setMsg(body);
        Mail.send(email);
    }

    public static void registerstep2() {
        render();
    }

    public static void registerstep2submit(String dni, String fullName, String ruc, String companyName) throws Exception {
        String email = Scope.Session.current().get("email");
        Subscriber byEmail = Subscriber.find("byEmail", email).first();
        byEmail.dni = dni;
        byEmail.fullName = fullName;
        byEmail.ruc = ruc;
        byEmail.companyName = companyName;
        byEmail.save();
        flash.success("Su información fue registrada exitosamente. A continuación deberá firmar el contrato de aceptación de servicio.");
        index();
    }

    public static void registerstep3() {
        render();
    }

    public static void registerstep3submit(File dni, File ruc, File powerOfAttorney) throws Exception {
        // If any of the files is missing then return an error
        if (dni == null || ruc == null || powerOfAttorney == null) {
            flash.error("Todos los documentos son requeridos.");
            registerstep3();
        }
        
        Subscriber currentSubscriber = getCurrentSubscriber();
        // Convert the dni file to Base64
        currentSubscriber.dniFile = convertToBase64(dni);
        currentSubscriber.fichaRucFile = convertToBase64(ruc);
        currentSubscriber.powerOfAttorneyFile = convertToBase64(powerOfAttorney);
        currentSubscriber.save();
        String message = "Sus documentos adjuntos fueron registrados exitosamente. Un agente de validación procederá a validarlos y usted será notificado.";
        flash.success(message);
        sendEmail(currentSubscriber.email, "IS283 - Aplicación de firma - Documentos en proceso de validación", message);
        index();
    }

    private static String convertToBase64(File file) throws IOException {
        if (file == null) {
            return null;
        }
        Base64.Encoder encoder = Base64.getEncoder();
        byte[] bytes = new byte[(int) file.length()];
        java.io.FileInputStream fileInputStream = new java.io.FileInputStream(file);
        fileInputStream.read(bytes);
        return encoder.encodeToString(bytes);
    }

    public static void verify(String email, String code) throws Exception {
        // Verify the code 
        GenericModel.JPAQuery byEmailAndCode = Subscriber.find("byEmailAndEmailVerificationCodeAndEmailVerified", email, code, false);
        List<Object> fetch = byEmailAndCode.fetch();
        if (fetch.size() > 0) {
            Subscriber subscriber = (Subscriber) fetch.get(0);
            subscriber.emailVerified = true;
            subscriber.save();
            flash.success("Su correo fue verificado correctamente. A continuación se requiere que provea información adicional.");
            Scope.Session.current().put("email", email);
            registerstep2();
        } else {
            flash.error("El vínculo de verificación no funcionó correctamente o la cuenta puede haber sido verificada anteriormente.");
            login();
        }

        render();
    }

    public static void login() throws Exception {
        // If logged in go to index
        String email = Scope.Session.current().get("email");
        if (email != null) {
            index();
        }
        render();
    }

    // Logout
    public static void logout() throws Exception {
        Scope.Session.current().clear();
        flash.success("Cierre de sesión exitoso.");
        login();
    }

    public static void loginPost(String emailAddress, String password) throws Exception {
        if (emailAddress.equals("validador@contoso.com") && password.equals("secret")) {
            flash.success("Inicio de sesión como validador exitoso.");
            Scope.Session.current().put("email", emailAddress);
            index();
        } else {
            GenericModel.JPAQuery query = Subscriber.find("byEmailAndPassword", emailAddress, password);
            List<Subscriber> fetch = query.fetch();
            if (!fetch.isEmpty()) {
                Subscriber subscriber = fetch.get(0);

                flash.success("Inicio de sesión exitoso.");

                Scope.Session.current().put("email", emailAddress);
                index();
            } else {
                flash.error("Usuario no existe, credenciales incorrectas o correo electrónico no verificado.");
                login();
            }
        }
    }

    public static void signcontract() {
        render();
    }

    public static void signcontractsubmit(String signaturesvg) throws Exception {
        Subscriber currentSubscriber = getCurrentSubscriber();
        currentSubscriber.signatureSvg = signaturesvg;
        currentSubscriber.save();
        flash.success("Firma de aceptación de servicio registrada exitosamente. Ahora debe proveer documentos adicionales para validación.");
        index();
    }

    public static void requestcertificate() {
        Subscriber subscriber = getCurrentSubscriber();
        render(subscriber);
    }

    public static void requestcertificatesubmit(String pin, String pinConfirmation) throws Exception {

        if (!pin.equals(pinConfirmation)) {
            flash.error("Los PINs no coinciden.");
            requestcertificate();
        }

        Subscriber subscriber = getCurrentSubscriber();
        // TODO use organizationIdentifier instead of a plain OU.
        String subjectDN = "emailAddress=" + subscriber.email + ", serialNumber=IDCPE-" + subscriber.dni + ", CN=" + subscriber.fullName + ", OU=VATPE-" + subscriber.ruc + ", O=" + subscriber.companyName + ", C=PE";

        // Generate a key pair for the subscriber
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Load the root CA
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream("conf/rootca.pfx"), "secret".toCharArray());
        String alias = keyStore.aliases().nextElement();
        X509Certificate rootCertificate = (X509Certificate) keyStore.getCertificate(alias);
        PrivateKey rootPrivateKey = (PrivateKey) keyStore.getKey(alias, "secret".toCharArray());

        // Create the new certificate
        X500Principal issuer = rootCertificate.getSubjectX500Principal();
        rootCertificate.getSubjectDN().getName();

        // Create principal for the subject
        X500Principal subject = new X500Principal(subjectDN);
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365 * 24 * 60 * 60 * 1000L); // 1 year validity
        JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(issuer, serial, notBefore, notAfter, subject, keyPair.getPublic());

        // Add extensions
        certificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        // Sign the certificate
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider("BC").build(rootPrivateKey);
        X509CertificateHolder certificateHolder = certificateBuilder.build(signer);

        // Convert to X509Certificate
        X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder);

        // Create a new PKCS #12 keystore
        KeyStore pkcs12Keystore = KeyStore.getInstance("PKCS12");
        pkcs12Keystore.load(null, null);

        // Store the subscriber's private key and the new certificate in the keystore
        pkcs12Keystore.setKeyEntry(subscriber.email, keyPair.getPrivate(), pin.toCharArray(), new Certificate[]{certificate});

        // Save the keystore to a file
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            pkcs12Keystore.store(bos, pin.toCharArray());
            // Convert BOS to Base64
            Base64.Encoder encoder = Base64.getEncoder();
            String p12Certificate = encoder.encodeToString(bos.toByteArray());
            subscriber.certificateP12 = p12Certificate;

        }
        // Convert certificate to PEM with Bouncy Castle and store in subscriber.certificatePem
        StringWriter writer = new StringWriter();
        PEMWriter pemWriter = new PEMWriter(writer);
        pemWriter.writeObject(certificate);
        pemWriter.flush();
        subscriber.certificatePem = writer.toString();

        subscriber.save();
        
        String string = certificate.toString();
        sendEmail(subscriber.email, "IS283 - Aplicación de firma - Certificado generado", "Su certificado fue generado exitosamente.\n\nA continuación se muestra la información del certificado: \n\n" + string);
        flash.success("Certificado generado exitosamente.");
        index();
    }

    public static void uploaddocforsignature(File file) throws Exception {
        Subscriber currentSubscriber = getCurrentSubscriber();
        PdfDocument pdfDocument = new PdfDocument();
        pdfDocument.pdfContent = convertToBase64(file);
        pdfDocument.subscriber = currentSubscriber;
        pdfDocument.pdfName = file.getName();
        pdfDocument.save();
        flash.success("El documento PDF fue subido correctamente.");
        signaturestart();
    }

    public static void downloadpdf(Integer id, boolean inline) throws Exception {
        PdfDocument pdfDocument = PdfDocument.findById(id);
        byte[] decode = b64Decode(pdfDocument.pdfContent);
        renderBinary(new java.io.ByteArrayInputStream(decode), pdfDocument.pdfName, inline);
    }

    public static void downloadsignedpdf(Integer id) throws Exception {
        PdfDocument pdfDocument = PdfDocument.findById(id);
        byte[] decode = b64Decode(pdfDocument.signedPdfContent);
        String pdfName = pdfDocument.pdfName;
        // Append "_signed" to the file name
        pdfName = pdfName.substring(0, pdfName.lastIndexOf(".")) + "_signed" + pdfName.substring(pdfName.lastIndexOf("."));
        renderBinary(new java.io.ByteArrayInputStream(decode), pdfName);
    }

    public static void signpdf(Integer id) throws Exception {
        PdfDocument pdfDocument = PdfDocument.findById(id);
        render(pdfDocument);
    }

    public static void signpdfsubmit(Integer id, String pin) throws Exception {
        PdfDocument pdfDocument = PdfDocument.findById(id);

        String certificateP12 = pdfDocument.subscriber.certificateP12;
        byte[] bytes = b64Decode(certificateP12);

        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
        try {
            keyStore.load(new ByteArrayInputStream(bytes), pin.toCharArray());
        } catch (IOException e) {
            // If "wrong password"
            if (e.getMessage().contains("wrong password")) {
                flash.error("PIN incorrecto.");
                signpdf(id);
            } else {
                throw e;
            }
        } 
        String alias = keyStore.aliases().nextElement();
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
        Certificate[] certificateChain = keyStore.getCertificateChain(alias);

        ByteArrayOutputStream signedPdfDocument = new ByteArrayOutputStream();
        PDDocument doc = PDDocument.load(new ByteArrayInputStream(b64Decode(pdfDocument.pdfContent)));

        PDSignature signature = new PDSignature();
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
//        signature.setName("Example User");
//        signature.setLocation("Los Angeles, CA");
//        signature.setReason("Testing");
        // TODO extract the above details from the signing certificate? Reason as a parameter?

        // the signing date, needed for valid signature
        signature.setSignDate(Calendar.getInstance());

        SignatureOptions signatureOptions = new SignatureOptions();
        // Size can vary, but should be enough for purpose.
        signatureOptions.setPreferredSignatureSize(SignatureOptions.DEFAULT_SIGNATURE_SIZE * 2);
        // register signature dictionary and sign interface
        doc.addSignature(signature, new SignatureInterface() {
            @Override
            public byte[] sign(InputStream inputStream) throws IOException {
                // cannot be done private (interface)
                try {
                    CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
                    X509Certificate cert = (X509Certificate) certificateChain[0];
                    ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA256WithRSA").build(privateKey);
                    gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(sha1Signer, cert));
                    gen.addCertificates(new JcaCertStore(Arrays.asList(certificateChain)));
                    CMSProcessableInputStream msg = new CMSProcessableInputStream(inputStream);
                    CMSSignedData signedData = gen.generate(msg, false);
                    return signedData.getEncoded();
                } catch (GeneralSecurityException e) {
                    throw new IOException(e);
                } catch (CMSException e) {
                    throw new IOException(e);
                } catch (OperatorCreationException e) {
                    throw new IOException(e);
                }
            }
        }, signatureOptions);

        // write incremental (only for signing purpose)
        doc.saveIncremental(signedPdfDocument);
        doc.close();

        pdfDocument.signedPdfContent = Base64.getEncoder().encodeToString(signedPdfDocument.toByteArray());

        pdfDocument.save();
        flash.success("El documento PDF fue firmado correctamente.");
        signaturestart();
    }
}
