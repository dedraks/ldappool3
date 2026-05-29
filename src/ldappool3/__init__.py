import queue
import threading
from ldap3 import Server, Connection, ALL, Tls, SUBTREE, ALL_ATTRIBUTES, MODIFY_REPLACE, MODIFY_ADD, MODIFY_DELETE
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
    def __init__(self, server_url, user, password, pool_size=5, use_pooling=True):
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
        use_pooling : bool, optional
            Se deve usar pooling de conexões, por padrão True.
        """
        self.server = Server(
            server_url, get_info='ALL',
            use_ssl=server_url.startswith('ldaps://'),
            tls=tls_configuration
        )
        self.user = user
        self.password = password
        self.pool_size = pool_size
        self.use_pooling = use_pooling
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
            # Check if connection is still alive, if not, refresh it
            if conn.closed:
                conn = self._create_connection()
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
            try:
                self._pool.put_nowait(conn)
            except queue.Full:
                conn.unbind() # If pool is somehow full, discard it safely

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
            return self.conn

        def __exit__(self, exc_type, exc_val, exc_tb):
            self.pool.return_connection(self.conn)

    def acquire(self):
        """
        Fornece um contexto para adquirir uma conexão do pool usando a sintaxe 'with'.
        
        Returns
        -------
        ConnectionContext
            Um contexto para gerenciar a conexão do pool.
        """
        return self.ConnectionContext(self)

    def __str__(self):
        """
        Retorna uma representação em string do estado atual do pool de conexões.
        
        Returns
        -------
        str
            Uma string representando o estado do pool de conexões.
        """
        table = ''
        for conn in list(self._pool.queue):
            table += f"{conn}\n"


        return table