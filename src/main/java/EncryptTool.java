import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.apache.commons.io.IOUtils;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.utils.Base64;
import org.bouncycastle.openssl.PEMWriter;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * http://www.devx.com/xml/Article/28701
 * 
 * The EncryptTool class reads input from a file, encrypts the contents
 * of the file, and then stores the encrypted file to disk. In order to
 * accomplish this, the tool uses the Apache XML framework to create two
 * symmetric keys for the following purposes:
 * 1) to encrypt the actual XML-file data
 * 2) to encrypt the key used to encrypt the XML-file data
 * 
 * The encrypted data is written to disk and the key used to encrypt the
 * data-encryption key is also stored to disk.
 * 
 * @author <a href="mailto:jeff@jeffhanson.com">Jeff Hanson</a>
 * @version $Revision: 1.1 $
 *          <p/>
 *          <p>
 *          <b>Revisions:</b>
 *          <p/>
 *          <p>
 *          <b>Jul 6, 2005 jhanson:</b>
 *          <ul>
 *          <li>Created file.
 *          </ul>
 */

public class EncryptTool {

	public static String PRIVATE_KEY = "private.pem";
	
	static {
		org.apache.xml.security.Init.init();
	}

	private static Document parseFile(String fileName) throws Exception {
		javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
		Document document = db.parse(fileName);

		return document;
	}

	private static Key GenerateKeyEncryptionKey() throws Exception {
		KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
		KeyPair p = g.generateKeyPair();
		File pk = new File(PRIVATE_KEY);
		PEMWriter pw = new PEMWriter(new FileWriter(pk));
		pw.writeObject(p.getPrivate());
		pw.close();
		System.out.println("Private Key stored in: " + pk.toURL().toString());		
		return p.getPublic();
	}

	private static SecretKey GenerateSymmetricKey() throws Exception {
		String jceAlgorithmName = "AES";
		KeyGenerator keyGenerator = KeyGenerator.getInstance(jceAlgorithmName);
		keyGenerator.init(128);
		return keyGenerator.generateKey();
	}

	private static void writeEncryptedDocToFile(Document doc, String fileName)
			throws Exception {
		File encryptionFile = new File(fileName);
		FileOutputStream outStream = new FileOutputStream(encryptionFile);

		TransformerFactory factory = TransformerFactory.newInstance();
		Transformer transformer = factory.newTransformer();
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
		DOMSource source = new DOMSource(doc);
		StreamResult result = new StreamResult(outStream);
		transformer.transform(source, result);

		outStream.close();

		System.out.println("Encrypted XML document written to: " + encryptionFile.toURL().toString());
	}

	private static void usage() {
		System.err.println("usage - java EncryptTool " + "infilename outfilename elementtoencrypt");
		System.err.println("example - java EncryptTool " + "test.xml encrypted.xml CreditCardNumber");
	}

	public static void main(String args[]) throws Exception {

		if (args.length < 2) {
			usage();
			System.exit(1);
		}

		Document document = loadBinary(args[0]);

		// parse file into document
		// Document document = parseFile(args[0]);

		// generate symmetric key
		Key symmetricKey = GenerateSymmetricKey();

		// Get a key to be used for encrypting the symmetric key
		Key keyEncryptKey = GenerateKeyEncryptionKey();

		// initialize cipher
		XMLCipher keyCipher = XMLCipher.getInstance(XMLCipher.RSA_OAEP);
		keyCipher.init(XMLCipher.WRAP_MODE, keyEncryptKey);

		// encrypt symmetric key
		EncryptedKey encryptedKey = keyCipher.encryptKey(document, symmetricKey);

		// specify the element to encrypt
		Element rootElement = document.getDocumentElement();
		Element elementToEncrypt = rootElement;
		if (args.length > 2) {
			elementToEncrypt = (Element) rootElement.getElementsByTagName(args[2]).item(0);
			if (elementToEncrypt == null) {
				System.err.println("Unable to find element: " + args[2]);
				System.exit(1);
			}
		}

		// initialize cipher
		XMLCipher xmlCipher = XMLCipher.getInstance(XMLCipher.AES_128);
		xmlCipher.init(XMLCipher.ENCRYPT_MODE, symmetricKey);

		// add key info to encrypted data element
		EncryptedData encryptedDataElement = xmlCipher.getEncryptedData();
		KeyInfo keyInfo = new KeyInfo(document);
		keyInfo.add(encryptedKey);
		encryptedDataElement.setKeyInfo(keyInfo);

		// do the actual encryption
		boolean encryptContentsOnly = true;
		xmlCipher.doFinal(document, elementToEncrypt, encryptContentsOnly);

		// write the results to a file
		writeEncryptedDocToFile(document, args[1]);
	}

	/**
	 * opakownie pliku binarnego w XML
	 * <?xml version="1.0" encoding="UTF-8"?><binary>......</binary>
	 * wartosc binary jest zawartoscia pliku zakodowana w Base64
	 * 
	 * @param string
	 * @return
	 * @throws Exception
	 */
	private static Document loadBinary(String string) throws Exception {
		DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
		DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
		Document doc = docBuilder.newDocument();
		Element rootElement = doc.createElement("binary");
		rootElement.appendChild(doc.createTextNode(new String(Base64.encode(IOUtils.toByteArray(new FileInputStream(string))))));
		doc.appendChild(rootElement);
		return doc;
	}
}
