package dam.psp.ex20230315;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

@TestMethodOrder(MethodOrderer.MethodName.class)
class ServidorUnitTest {

	static KeyStore ks;

	@BeforeAll
	static void setUpBeforeClass() throws Exception {
		ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(ServidorUnitTest.class.getResourceAsStream("/keystore_RSA.p12"), "practicas".toCharArray());
	}

	@Test
	@DisplayName("(0,2 puntos) No se envía petición (A)")
	void test01() {
		try (Socket socket = new Socket("localhost", 9000)) {
			socket.setSoTimeout(10000);
			assertEquals("ERROR:Read timed out", new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}

	@Test
	@DisplayName("(0,2 puntos) No se envía petición (B)")
	void test02() {
		try (Socket socket = new Socket("localhost", 9000)) {
			socket.setSoTimeout(10000);
			socket.shutdownOutput();
			assertEquals("ERROR:Se esperaba una petición", new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}

	@Test
	@DisplayName("(0,2 puntos) Petición incorrecta (A)")
	void test03() {
		try (Socket socket = new Socket("localhost", 9000)) {
			socket.setSoTimeout(10000);
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("abcd");
			assertEquals("ERROR:'abcd' no se reconoce como una petición válida",
					new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}

	@Test
	@DisplayName("(0,2 puntos) Petición incorrecta (B)")
	void test04() {
		try (Socket socket = new Socket("localhost", 9000)) {
			socket.setSoTimeout(10000);
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("abcd");
			socket.shutdownOutput();
			assertEquals("ERROR:'abcd' no se reconoce como una petición válida",
					new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}

	@Test
	@DisplayName("(1,4 puntos) Petición \"hash\"")
	void test05() {
		String mensaje = "MENSAJE DE PRUEBA";
		for (String algoritmo : new String[] { "SHA-256", "MD5", "SHA3-512" }) {
			try (Socket socket = new Socket("localhost", 9000)) {
				socket.setSoTimeout(1000);
				MessageDigest md;
				md = MessageDigest.getInstance(algoritmo);
				String hashB64 = Base64.getEncoder().encodeToString(md.digest(mensaje.getBytes()));

				DataOutputStream out = new DataOutputStream(socket.getOutputStream());
				out.writeUTF("hash");
				out.writeUTF(algoritmo);
				out.write(mensaje.getBytes());
				socket.shutdownOutput();
				assertEquals("OK:" + hashB64, new DataInputStream(socket.getInputStream()).readUTF());
			} catch (IOException | NoSuchAlgorithmException e) {
				fail(e.getLocalizedMessage());
			}
		}
	}

	@Test
	@DisplayName("(0,2 puntos) Petición \"hash\" sin algoritmo (A)")
	void test06() {
		try (Socket socket = new Socket("localhost", 9000)) {
			socket.setSoTimeout(10000);

			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("hash");

			assertEquals("ERROR:Read timed out", new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}

	@Test
	@DisplayName("(0,2 puntos) Petición \"hash\" sin algoritmo (B)")
	void test07() {
		try (Socket socket = new Socket("localhost", 9000)) {
			socket.setSoTimeout(10000);

			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("hash");
			socket.shutdownOutput();

			assertEquals("ERROR:Se esperaba un algoritmo", new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}

	@Test
	@DisplayName("(0,2 puntos) Petición \"hash\" sin datos (A)")
	void test08() {
		try (Socket socket = new Socket("localhost", 9000)) {
			socket.setSoTimeout(10000);

			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("hash");
			out.writeUTF("SHA-256");

			assertEquals("ERROR:Read timed out", new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}

	@Test
	@DisplayName("(0,2 puntos) Petición \"hash\" sin datos (B)")
	void test09() {
		try (Socket socket = new Socket("localhost", 9000)) {
			socket.setSoTimeout(10000);

			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("hash");
			out.writeUTF("SHA-256");
			socket.shutdownOutput();

			assertEquals("ERROR:Se esperaban datos", new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}

	@Test
	@DisplayName("(0,2 puntos) Petición \"hash\" cliente no envía EOF")
	void test10() {
		String mensaje = "MENSAJE DE PRUEBA";
		try (Socket socket = new Socket("localhost", 9000)) {
			socket.setSoTimeout(10000);

			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("hash");
			out.writeUTF("SHA-256");
			out.write(mensaje.getBytes());

			assertEquals("ERROR:Read timed out", new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}

	@Test
	@DisplayName("(1,4 puntos) Petición \"cert\"")
	void test11() {
		try (Socket socket = new Socket("localhost", 9000)) {
			socket.setSoTimeout(1000);
			String b64 = Base64.getEncoder().encodeToString(ks.getCertificate("psp").getEncoded());
			MessageDigest md;
			md = MessageDigest.getInstance("SHA-256");
			md.update(b64.getBytes());
			String b64HashB64 = Base64.getEncoder().encodeToString(md.digest());
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cert");
			out.writeUTF("psp");
			out.writeUTF(b64);
			socket.shutdownOutput();

			assertEquals("OK:" + b64HashB64, new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException | CertificateEncodingException | NoSuchAlgorithmException | KeyStoreException e) {
			fail(e.getLocalizedMessage());
		}
	}

	@Test
	@DisplayName("(0,2 puntos) Petición \"cert\" sin alias (A)")
	void test12() {
		try (Socket socket = new Socket("localhost", 9000)) {
			socket.setSoTimeout(10000);

			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cert");

			assertEquals("ERROR:Read timed out", new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}

	@Test
	@DisplayName("(0,2 puntos) Petición \"cert\" sin alias (B)")
	void test13() {
		try (Socket socket = new Socket("localhost", 9000)) {
			socket.setSoTimeout(10000);

			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cert");
			socket.shutdownOutput();

			assertEquals("ERROR:Se esperaba un alias", new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}

	@Test
	@DisplayName("(0,2 puntos) Petición \"cert\" sin certificado (A)")
	void test14() {
		try (Socket socket = new Socket("localhost", 9000)) {
			socket.setSoTimeout(10000);

			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cert");
			out.writeUTF("psp");

			assertEquals("ERROR:Read timed out", new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}

	@Test
	@DisplayName("(0,2 puntos) Petición \"cert\" sin certificado (B)")
	void test15() {
		try (Socket socket = new Socket("localhost", 9000)) {
			socket.setSoTimeout(10000);

			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cert");
			out.writeUTF("psp");
			socket.shutdownOutput();

			assertEquals("ERROR:Se esperaba un certificado", new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}

	@Test
	@DisplayName("(0,2 puntos) Petición \"cert\" envía datos sin codificar en Base64 (B)")
	void test16() {
		try (Socket socket = new Socket("localhost", 9000)) {
			socket.setSoTimeout(10000);

			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cert");
			out.writeUTF("psp");
			out.writeUTF("*****");

			assertEquals("ERROR:Se esperaba Base64", new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}

	@Test
	@DisplayName("(3 puntos) Petición \"cifrar\"")
	void test17() {
		String texto = "Por cuanto por parte de vos, Miguel de Cervantes, nos fue fecha relación\n"
				+ "que habíades compuesto un libro intitulado El ingenioso hidalgo de la\n"
				+ "Mancha, el cual os había costado mucho trabajo y era muy útil y provechoso,\n"
				+ "nos pedistes y suplicastes os mandásemos dar licencia y facultad para le\n"
				+ "poder imprimir, y previlegio por el tiempo que fuésemos servidos, o como la\n"
				+ "nuestra merced fuese; lo cual visto por los del nuestro Consejo, por cuanto\n"
				+ "en el dicho libro se hicieron las diligencias que la premática últimamente\n"
				+ "por nos fecha sobre la impresión de los libros dispone, fue acordado que\n"
				+ "debíamos mandar dar esta nuestra cédula para vos, en la dicha razón; y nos\n"
				+ "tuvímoslo por bien. Por la cual, por os hacer bien y merced, os damos\n"
				+ "licencia y facultad para que vos, o la persona que vuestro poder hubiere, y\n"
				+ "no otra alguna, podáis imprimir el dicho libro, intitulado El ingenioso\n"
				+ "hidalgo de la Mancha, que desuso se hace mención, en todos estos nuestros\n"
				+ "reinos de Castilla, por tiempo y espacio de diez años, que corran y se\n"
				+ "cuenten desde el dicho día de la data desta nuestra cédula; so pena que la\n"
				+ "persona o personas que, sin tener vuestro poder, lo imprimiere o vendiere,\n"
				+ "o hiciere imprimir o vender, por el mesmo caso pierda la impresión que\n"
				+ "hiciere, con los moldes y aparejos della; y más, incurra en pena de\n"
				+ "cincuenta mil maravedís cada vez que lo contrario hiciere. La cual dicha\n"
				+ "pena sea la tercia parte para la persona que lo acusare, y la otra tercia\n"
				+ "parte para nuestra Cámara, y la otra tercia parte para el juez que lo\n"
				+ "sentenciare. Con tanto que todas las veces que hubiéredes de hacer imprimir\n"
				+ "el dicho libro, durante el tiempo de los dichos diez años, le traigáis al\n"
				+ "nuestro Consejo, juntamente con el original que en él fue visto, que va\n"
				+ "rubricado cada plana y firmado al fin dél de Juan Gallo de Andrada, nuestro\n"
				+ "Escribano de Cámara, de los que en él residen, para saber si la dicha\n"
				+ "impresión está conforme el original; o traigáis fe en pública forma de cómo\n"
				+ "por corretor nombrado por nuestro mandado, se vio y corrigió la dicha\n"
				+ "impresión por el original, y se imprimió conforme a él, y quedan impresas\n"
				+ "las erratas por él apuntadas, para cada un libro de los que así fueren\n"
				+ "impresos, para que se tase el precio que por cada volume hubiéredes de\n"
				+ "haber. Y mandamos al impresor que así imprimiere el dicho libro, no imprima\n"
				+ "el principio ni el primer pliego dél, ni entregue más de un solo libro con\n"
				+ "el original al autor, o persona a cuya costa lo imprimiere, ni otro alguno,\n"
				+ "para efeto de la dicha correción y tasa, hasta que antes y primero el dicho\n"
				+ "libro esté corregido y tasado por los del nuestro Consejo; y, estando\n"
				+ "hecho, y no de otra manera, pueda imprimir el dicho principio y primer\n"
				+ "pliego, y sucesivamente ponga esta nuestra cédula y la aprobación, tasa y\n"
				+ "erratas, so pena de caer e incurrir en las penas contenidas en las leyes y\n"
				+ "premáticas destos nuestros reinos. Y mandamos a los del nuestro Consejo, y\n"
				+ "a otras cualesquier justicias dellos, guarden y cumplan esta nuestra cédula\n"
				+ "y lo en ella contenido. Fecha en Valladolid, a veinte y seis días del mes\n"
				+ "de setiembre de mil y seiscientos y cuatro años.";
		StringBuilder sb = new StringBuilder();
		try (Socket socket = new Socket("localhost", 9000)) {
			socket.setSoTimeout(10000);
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cifrar");
			out.writeUTF("psp");
			out.write(texto.getBytes());
			socket.shutdownOutput();
			DataInputStream in = new DataInputStream(socket.getInputStream());
			Key key = ks.getKey("psp", "practicas".toCharArray());
			Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			while (true) {
				c.init(Cipher.DECRYPT_MODE, key);
				String[] s = in.readUTF().split(":");
				assertEquals("OK", s[0]);
				sb.append(new String(c.doFinal(Base64.getDecoder().decode(s[1]))));
			}
		} catch (EOFException e) {
			assertEquals(sb.toString(), texto);
		} catch (IOException e) {
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
	}

	@Test
	@DisplayName("(0,2 puntos) Petición \"cifrar\" sin alias (A)")
	void test18() {
		try (Socket socket = new Socket("localhost", 9000)) {
			socket.setSoTimeout(10000);

			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cifrar");

			assertEquals("ERROR:Read timed out", new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}

	@Test
	@DisplayName("(0,2 puntos) Petición \"cifrar\" sin alias (B)")
	void test19() {
		try (Socket socket = new Socket("localhost", 9000)) {
			socket.setSoTimeout(10000);

			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cifrar");
			socket.shutdownOutput();

			assertEquals("ERROR:Se esperaba un alias", new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}

	@Test
	@DisplayName("(0,2 puntos) Petición \"cifrar\" el alias no es válido")
	void test20() {
		try (Socket socket = new Socket("localhost", 9000)) {
			socket.setSoTimeout(10000);

			String texto = "En un lugar de la Mancha, de cuyo nombre no quiero acordarme ...";

			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cifrar");
			out.writeUTF("aliasnoválido");
			out.write(texto.getBytes());
			socket.shutdownOutput();

			assertEquals("ERROR:'aliasnoválido' no es un certificado",
					new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}

	@Test
	@DisplayName("(0,2 puntos) Petición \"cifrar\" el certificado no contiene una clave RSA")
	void test21() {
		try (Socket socket = new Socket("localhost", 9000)) {
			socket.setSoTimeout(1000);
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cert");
			out.writeUTF("alumno");
			out.writeUTF(Base64.getEncoder().encodeToString(ks.getCertificate("alumno").getEncoded()));

			new DataInputStream(socket.getInputStream()).readUTF();
		} catch (IOException | CertificateEncodingException | KeyStoreException e) {
			fail(e.getLocalizedMessage());
		}

		try (Socket socket = new Socket("localhost", 9000)) {
			socket.setSoTimeout(10000);

			String texto = "En un lugar de la Mancha, de cuyo nombre no quiero acordarme ...";

			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cifrar");
			out.writeUTF("alumno");
			out.write(texto.getBytes());
			socket.shutdownOutput();

			assertEquals("ERROR:'alumno' no contiene una clave RSA",
					new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}

	@Test
	@DisplayName("(0,2 puntos) Petición \"cifrar\" cliente no envía EOF")
	void test22() {
		try (Socket socket = new Socket("localhost", 9000)) {
			socket.setSoTimeout(10000);

			String texto = "En un lugar de la Mancha, de cuyo nombre no quiero acordarme ...";

			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cifrar");
			out.writeUTF("psp");
			out.write(texto.getBytes());
			DataInputStream in = new DataInputStream(socket.getInputStream());
			String s = null;
			try {
				while (true)
					s = in.readUTF();
			} catch (EOFException e) {
				assertTrue(s != null);
				assertEquals("ERROR:Read timed out", s);
			}
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}

	@Test
	@DisplayName("(0,2 puntos) Petición \"cifrar\" no se envían datos (A)")
	void test23() {
		try (Socket socket = new Socket("localhost", 9000)) {
			socket.setSoTimeout(10000);

			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cifrar");
			out.writeUTF("psp");

			assertEquals("ERROR:Read timed out", new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}

	@Test
	@DisplayName("(0,2 puntos) Petición \"cifrar\" no se envían datos (B)")
	void test24() {
		try (Socket socket = new Socket("localhost", 9000)) {
			socket.setSoTimeout(10000);

			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cifrar");
			out.writeUTF("psp");
			socket.shutdownOutput();

			assertEquals("ERROR:Se esperaban datos", new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}

}