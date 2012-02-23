module APNS
  require 'socket'
  require 'openssl'
  require 'json'

  class PemPathError < RuntimeError;end
  class PemFileError < RuntimeError;end

  ## Host for push notification service
  #
  # production: gateway.push.apple.com
  # development: gateway.sandbox.apple.com
  #
  # You may set the correct host with:
  # APNS.host = <host> or use the default one
  @host = 'gateway.sandbox.push.apple.com'
  @port = 2195

  ## Host for feedback service
  #
  # production: feedback.push.apple.com
  # development: feedback.sandbox.apple.com
  #
  # You may set the correct feedback host with:
  # APNS.feedback_host = <host> or use the default one
  @feedback_host = @host.gsub('gateway','feedback')
  @feedback_port = 2196

  # openssl pkcs12 -in mycert.p12 -out client-cert.pem -nodes -clcerts
  @pem = {} # this should be the path of the pem file not the contents
  @pass = {}

  # Persistent connection
  @@ssl = {}
  @@sock = {}

  class << self
    attr_accessor :host, :port, :feedback_host, :feedback_port, :logger
    def pem(stream = :_global, new_pem = nil)
      @pem[stream] = new_pem if new_pem
      @pem[stream]
    end
    def pem=(new_pem); @pem[:_global] = new_pem; end

    def pass(stream = :_global, new_pass = nil)
      @pass[stream] = new_pass if new_pass
      @pass[stream]
    end
    def pass=(new_pass); @pass[:_global] = new_pass; end
  end

  # send one or many payloads
  #
  # Connection
  #   The connection is made only if needed and is persisted until it times out or is closed by the system
  #
  # Errors
  #   If an error occures during the write operation, after 3 retries, the socket and ssl connections are closed and an exception is raised
  #
  # Example:
  #
  #  single payload
  # payload = APNS::Payload.new(device_token, 'Hello iPhone!')
  # APNS.send_payloads(payload)
  #
  #  or with multiple payloads
  # APNS.send_payloads([payload1, payload2])


  # Send to a pem stream
  def self.send_stream(stream, *payloads)
    payloads.flatten!

    # retain valid payloads only
    payloads.reject!{ |p| !(p.is_a?(APNS::Payload) && p.valid?) }

    return if (payloads.nil? || payloads.count < 1)

    # loop through each payloads
    payloads.each do |payload|
      retry_delay = 2

      # !ToDo! do a better job by using a select to poll the socket for a possible response from apple to inform us about an error in the sent payload
      #
      begin
        @@sock[stream], @@ssl[stream] = self.push_connection(stream) if @@ssl[stream].nil?
        @@ssl[stream].write(payload.to_ssl); @@ssl[stream].flush
      rescue PemPathError, PemFileError => e
        raise e
      rescue
        @@ssl[stream].close; @@sock[stream].close
        @@ssl[stream] = nil; @@sock[stream] = nil # cleanup

        retry_delay *= 2
        if retry_delay <= 8
          logger.warn "Failed to write payload, sleeping for #{retry_delay}s!" if logger.present?
          sleep retry_delay
          retry
        else
          raise
        end
      end # begin block

    end # each payloads
  end

  def self.send_payloads(*payloads)
    self.send(payloads)
  end

  def self.send(*payloads)
    self.send_stream(:_global, payloads)
  end


  def self.feedback(stream = :_global)
    sock, ssl = self.feedback_connection(stream)

    apns_feedback = []

    while line = sock.gets   # Read lines from the socket
      line.strip!
      f = line.unpack('N1n1H140')
      apns_feedback << [Time.at(f[0]), f[2]]
    end

    ssl.close
    sock.close

    return apns_feedback
  end


  protected

  def self.ssl_context(stream = :_global)
    raise PemPathError, "The path to your pem file is not set. (APNS.pem = /path/to/cert.pem)" unless self.pem(stream)
    raise PemFileError, "The path to your pem file does not exist!" unless File.exist?(self.pem(stream))

    context      = OpenSSL::SSL::SSLContext.new
    context.cert = OpenSSL::X509::Certificate.new(File.read(self.pem(stream)))
    context.key  = OpenSSL::PKey::RSA.new(File.read(self.pem(stream)), self.pass(stream))
    context
  end

  def self.connect_to(aps_host, aps_port, stream = :_global)
    context      = self.ssl_context(stream)
    sock         = TCPSocket.new(aps_host, aps_port)
    ssl          = OpenSSL::SSL::SSLSocket.new(sock, context)
    ssl.connect

    return sock, ssl
  end

  def self.push_connection(stream = :_global)
    self.connect_to(self.host, self.port, stream)
  end

  def self.feedback_connection(stream = :_global)
    self.connect_to(self.feedback_host, self.feedback_port, stream)
  end

end
