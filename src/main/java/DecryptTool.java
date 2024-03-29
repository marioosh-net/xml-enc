import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.ObjectInputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import org.apache.commons.io.IOUtils;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.utils.JavaUtils;
import org.apache.xml.security.utils.EncryptionConstants;
import org.apache.xml.security.utils.Base64;
import org.bouncycastle.openssl.PEMReader;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.OutputKeys;

/**
 * http://www.devx.com/xml/Article/28701
 * 
 * The DecryptTool class reads an encrypted file from disk,
 * decrypts the contents of the file using a previously-stored
 * key, and then stores the decrypted file to disk.
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

public class DecryptTool {

	static {
		org.apache.xml.security.Init.init();
	}

	private static Document loadEncryptedFile(String fileName) throws Exception {
		File encryptedFile = new File(fileName);
		javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		javax.xml.parsers.DocumentBuilder builder = dbf.newDocumentBuilder();
		Document document = builder.parse(encryptedFile);

		System.out.println("Encryption document loaded from: " + encryptedFile.toURL().toString());
		return document;
	}

	private static Key loadKeyEncryptionKey() throws Exception {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		PEMReader pr = new PEMReader(new FileReader(EncryptTool.PRIVATE_KEY));
		KeyPair k = (KeyPair) pr.readObject();
		pr.close();
		return k.getPrivate();
	}

	private static void writeDecryptedDocToFile(Document doc, String fileName)
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

		System.out.println("Decrypted data written to: " + encryptionFile.toURL().toString());
	}

	private static void usage() {
		System.err.println("usage - java DecryptTool " + "infile outfile");
		System.err.println("example - java DecryptTool " + "encrypted.xml original.xml");
	}

	public static void main(String args[]) throws Exception {
		if (args.length < 2) {
			usage();
			System.exit(1);
		}

		// load the encrypted file into a Document
		Document document = loadEncryptedFile(args[0]);

		// get the encrypted data element
		String namespaceURI = EncryptionConstants.EncryptionSpecNS;
		String localName = EncryptionConstants._TAG_ENCRYPTEDDATA;
		Element encryptedDataElement = (Element) document.getElementsByTagNameNS(namespaceURI, localName).item(0);

		// Load the key encryption key.
		Key keyEncryptKey = loadKeyEncryptionKey();

		// initialize cipher
		XMLCipher xmlCipher = XMLCipher.getInstance();
		xmlCipher.init(XMLCipher.DECRYPT_MODE, null);

		xmlCipher.setKEK(keyEncryptKey);

		// do the actual decryption
		xmlCipher.doFinal(document, encryptedDataElement);

		// write the results to a file
		writeDecryptedDocToFile(document, args[1]);

		// wyciagnij z xml binarny plik
		saveBinaryFromXmlToFile(args[1]);

	}

	/**
	 * wyciaga z xml noda <binary> i zamienia jego zawartosc z base64 na plik binarny INLINE 
	 * @param file - plik xml
	 * @throws Exception
	 */
	private static void saveBinaryFromXmlToFile(String file) throws Exception {
		javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
		IOUtils.copy(new ByteArrayInputStream(Base64.decode(((Element)db.parse(file).getElementsByTagName("binary").item(0)).getTextContent())), new FileOutputStream(file));

	}
}
