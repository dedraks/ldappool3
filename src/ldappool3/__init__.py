import queue
import threading
from ldap3 import Server, Connection, ALL, Tls, SUBTREE, ALL_ATTRIBUTES, MODIFY_REPLACE, MODIFY_ADD, MODIFY_DELETE
from ldap3.core.exceptions import LDAPSocketSendError, LDAPSocketReceiveError, LDAPBindError, LDAPSessionTerminatedByServerError
import ssl

class AD_SAM_ACCOUNT_TYPE:
    SAM_DOMAIN_OBJECT = 0x0
    SAM_GROUP_OBJECT = 0x10000000
    SAM_NON_SECURITY_GROUP_OBJECT = 0x10000001
    SAM_ALIAS_OBJECT = 0x20000000
    SAM_NON_SECURITY_ALIAS_OBJECT = 0x20000001
    SAM_USER_OBJECT = 0x30000000
    SAM_NORMAL_USER_ACCOUNT = 0x30000000
    SAM_MACHINE_ACCOUNT = 0x30000001
    SAM_TRUST_ACCOUNT = 0x30000002
    SAM_APP_BASIC_GROUP = 0x40000000
    SAM_APP_QUERY_GROUP = 0x40000001
    SAM_ACCOUNT_TYPE_MAX = 0x7fffffff

class AD_GROUP_TYPE_FLAGS:
    GLOBAL_GROUP = 0x00000002
    DOMAIN_LOCAL_GROUP = 0x00000004
    UNIVERSAL_GROUP = 0x00000008
    SECURITY_ENABLED = 0x80000000

class AD_USER_ACCOUNT_FLAGS:
    SCRIPT = 1
    ACCOUNTDISABLE = 2
    Undeclared = 4
    HOMEDIR_REQUIRED = 8
    LOCKOUT = 16
    PASSWD_NOTREQD = 32
    PASSWD_CANT_CHANGE = 64
    ENCRYPTED_TEXT_PWD_ALLOWED = 128
    TEMP_DUPLICATE_ACCOUNT = 256
    NORMAL_ACCOUNT = 512
    INTERDOMAIN_TRUST_ACCOUNT = 2048
    WORKSTATION_TRUST_ACCOUNT = 4096
    SERVER_TRUST_ACCOUNT = 8192
    DONT_EXPIRE_PASSWORD = 65536
    MNS_LOGON_ACCOUNT = 131072
    SMARTCARD_REQUIRED = 262144
    TRUSTED_FOR_DELEGATION = 524288
    NOT_DELEGATED = 1048576
    USE_DES_KEY_ONLY = 2097152
    DONT_REQ_PREAUTH = 4194304
    PASSWORD_EXPIRED = 8388608
    TRUSTED_TO_AUTH_FOR_DELEGATION = 16777216
    PARTIAL_SECRETS_ACCOUNT = 67108864

    GROUP_TYPE_SECURITY_ENABLED = 0x80000000



tls_configuration = Tls(validate=ssl.CERT_NONE)

class LDAPConnectionPool3:
    """
    Gerenciador de conexões LDAP com pooling para otimizar o desempenho em 
    aplicações de alta demanda.

    Exemplo de uso:
    pool = LDAPConnectionPool(server_url, user, password, pool_size=10)
    with pool.acquire() as conn:
        conn.search('dc=example,dc=com', '(objectClass=person)')
    """
    def __init__(self, server_url, user, password, pool_size=5):
        """
        Inicializa o pool de conexões LDAP.
        Parameters
        ----------
        server_url : str
            URL do servidor LDAP.
        user : str
            Usuário para autenticação.
        password : str
            Senha para autenticação.
        pool_size : int, optional
            Tamanho do pool de conexões, por padrão 5.
        """
        self.server = Server(
            server_url, get_info='ALL',
            use_ssl=server_url.startswith('ldaps://'),
            tls=tls_configuration
        )
        self.user = user
        self.password = password
        self.pool_size = pool_size
        self._pool = queue.Queue(maxsize=pool_size)
        self._lock = threading.Lock()
        
        # Pré-popula o pool com conexões autenticadas
        for _ in range(pool_size):
            conn = self._create_connection()
            self._pool.put(conn)

    def _create_connection(self):
        """
        Cria uma nova conexão LDAP autenticada.

        Returns
        -------
        Connection
            Uma nova conexão LDAP autenticada.
        """
        conn = Connection(
            self.server,
            user=self.user,
            password=self.password,
            auto_bind=True,
        )
        return conn

    def _refresh_connection(self, conn):
        """Validate or refresh a pooled ldap3 connection."""
        if conn is None:
            return self._create_connection()

        try:
            if conn.closed:
                return self._create_connection()

            # A simple rebind validates the socket state and reconnects if needed.
            if not conn.rebind():
                return self._create_connection()

            return conn
        except (LDAPSocketSendError, LDAPSocketReceiveError,
                LDAPBindError, LDAPSessionTerminatedByServerError):
            try:
                conn.unbind()
            except Exception:
                pass
            return self._create_connection()
        except Exception:
            try:
                conn.unbind()
            except Exception:
                pass
            return self._create_connection()

    def get_connection(self, timeout=5):
        """
        Obtém uma conexão do pool, aguardando até que uma esteja disponível 
        ou o timeout seja atingido.

        Parameters
        ----------
        timeout : int, optional
            Tempo máximo de espera por uma conexão disponível, por padrão 5 segundos.

        Returns
        -------
        Connection
            Uma conexão LDAP ativa e pronta para uso.
        """
        try:
            conn = self._pool.get(block=True, timeout=timeout)
            conn = self._refresh_connection(conn)
            return conn
        except queue.Empty:
            raise Exception("LDAP Connection Pool timeout: No available connections.")

    def return_connection(self, conn):
        """
        Retorna uma conexão ao pool.

        Parameters
        ----------
        conn : Connection
            A conexão LDAP a ser devolvida ao pool.
        """
        if conn:
            if conn.closed or not conn.bound:
                try:
                    conn.unbind()
                except Exception:
                    pass
                return

            try:
                self._pool.put_nowait(conn)
            except queue.Full:
                try:
                    conn.unbind()
                except Exception:
                    pass

    class ConnectionContext:
        """
        Context manager para facilitar o uso das conexões do pool com a sintaxe 'with'.
        """
        def __init__(self, pool):
            """
            Inicializa o contexto de conexão com referência ao pool.
            
            Parameters
            ----------
            pool : LDAPConnectionPool
                O pool de conexões LDAP.
            """
            self.pool = pool
            self.conn = None

        def __enter__(self):
            self.conn = self.pool.get_connection()
            if self.conn is None:
                raise Exception("Failed to acquire LDAP connection from pool.")
            if self.conn.closed or not self.conn.bound:
                self.conn = self.pool._create_connection()
            return self.conn

        def __exit__(self, exc_type, exc_val, exc_tb):
            if exc_type is not None:
                try:
                    self.conn.unbind()
                except Exception:
                    pass
                return False

            self.pool.return_connection(self.conn)
            return False

    class ConnectionContextWithRetry:
        """
        Context manager that wraps acquire with automatic retry on socket errors.
        Keeps the familiar 'with' syntax while providing reconnection logic.
        """
        def __init__(self, pool, retries=2, retry_delay=0.1):
            self.pool = pool
            self.retries = retries
            self.retry_delay = retry_delay
            self.conn = None
            self.attempt = 0

        def __enter__(self):
            last_exception = None
            for attempt in range(self.retries + 1):
                try:
                    self.conn = self.pool.get_connection()
                    if self.conn is None:
                        raise Exception("Failed to acquire LDAP connection from pool.")
                    if self.conn.closed or not self.conn.bound:
                        self.conn = self.pool._create_connection()
                    self.attempt = attempt
                    return self.conn
                except (LDAPSocketSendError, LDAPSocketReceiveError,
                        LDAPBindError, LDAPSessionTerminatedByServerError) as exc:
                    last_exception = exc
                    if attempt == self.retries:
                        raise
                    time.sleep(self.retry_delay)
                except Exception:
                    raise
            raise last_exception

        def __exit__(self, exc_type, exc_val, exc_tb):
            if exc_type in (LDAPSocketSendError, LDAPSocketReceiveError,
                            LDAPBindError, LDAPSessionTerminatedByServerError):
                # Socket/connection error occurred during operation, discard connection
                try:
                    self.conn.unbind()
                except Exception:
                    pass
                return False

            if exc_type is not None:
                try:
                    self.conn.unbind()
                except Exception:
                    pass
                return False

            self.pool.return_connection(self.conn)
            return False

    def acquire(self):
        """
        Fornece um contexto para adquirir uma conexão do pool usando a sintaxe 'with'.
        
        Returns
        -------
        ConnectionContext
            Um contexto para gerenciar a conexão do pool.
        """
        #return self.ConnectionContext(self)
        return self.acquire_with_retry()

    def acquire_with_retry(self, retries=2, retry_delay=0.1):
        """
        Fornece um contexto com retry automático para socket errors.
        Use esta versão quando quiser reconnect automático durante operações.
        
        Parameters
        ----------
        retries : int, optional
            Número de tentativas em caso de socket error (padrão: 2)
        retry_delay : float, optional
            Tempo de espera entre tentativas em segundos (padrão: 0.1)
        
        Returns
        -------
        ConnectionContextWithRetry
            Um contexto que faz retry automático em socket errors.
        """
        return self.ConnectionContextWithRetry(self, retries=retries, retry_delay=retry_delay)
    
    def __str__(self):
        table = ''
        for conn in list(self._pool.queue):
            table += f"{conn}\n"


        return table

