(ns pop3.transport
  "The wire boundary for POP3 (RFC 1939): a 3-fn `Transport` protocol
  (write!/read-line!/close!) that `pop3.client` drives and every other
  namespace in this library is blind to. The real transport
  (`tls-connect`) is JVM-only (a raw `SSLSocket`, implicit TLS on port
  995 -- POP3S); tests inject a fake in-memory `Transport` instead.

  Deliberately not shared code with `org-ietf-smtp`'s and
  `org-ietf-imap`'s identically-shaped transports -- same structural
  idea, three different protocols, kept independent per this org's
  grab-bag-library convention.")

(defprotocol Transport
  (write! [t s] "Write string `s` (already CRLF-terminated by the caller) to the wire.")
  (read-line! [t] "Read one CRLF-terminated line, without the terminator. nil on EOF.")
  (close! [t]))

#?(:clj
(deftype SocketTransport [^java.net.Socket socket
                          ^java.io.InputStream in
                          ^java.io.OutputStream out]
  Transport
  (write! [_ s]
    (.write out (.getBytes ^String s "UTF-8"))
    (.flush out))
  (read-line! [_]
    (let [buf (java.io.ByteArrayOutputStream.)]
      (loop []
        (let [b (.read in)]
          (cond
            (neg? b) (when (pos? (.size buf)) (.toString buf "UTF-8"))
            (= b 10) (let [bytes (.toByteArray buf)
                           len (alength bytes)]
                       (if (and (pos? len) (= (aget bytes (dec len)) (byte 13)))
                         (String. bytes 0 (dec len) "UTF-8")
                         (String. bytes 0 len "UTF-8")))
            :else (do (.write buf b) (recur)))))))
  (close! [_] (.close socket))))

#?(:clj
(defn tls-connect
  "Real transport: connect to `host`:`port` over TLS (default port 995,
  POP3S). `timeout-ms` bounds each individual socket read."
  [{:keys [host port timeout-ms] :or {port 995 timeout-ms 20000}}]
  (let [factory (javax.net.ssl.SSLSocketFactory/getDefault)
        socket (.createSocket ^javax.net.ssl.SSLSocketFactory factory ^String host (int port))]
    (.setSoTimeout ^javax.net.ssl.SSLSocket socket (int timeout-ms))
    (->SocketTransport socket (.getInputStream socket) (.getOutputStream socket)))))

#?(:clj
(defn plain-connect
  "Cleartext connect to `host`:`port` (default 110), for a session that
  will be upgraded with STLS (RFC 2595).

  Present because POP3 has the same two shapes SMTP does -- implicit TLS
  on 995, or cleartext on 110 upgraded in place -- and a host commonly
  offers one of the two. Nothing here sends a password before the
  upgrade; `client/stls!` is what makes the session safe to authenticate
  over, and `client/login!` on a transport that was never upgraded is the
  caller's decision to make knowingly."
  [{:keys [host port timeout-ms] :or {port 110 timeout-ms 20000}}]
  (let [socket (java.net.Socket. ^String host (int port))]
    (.setSoTimeout socket (int timeout-ms))
    (->SocketTransport socket (.getInputStream socket) (.getOutputStream socket)))))
