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

  @@timings = {}

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

  def self.time_logged label
    start = Time.now.to_f
    (yield).tap do
      @@timings[label] ||= 0
      @@timings[label] += Time.now.to_f - start
    end
  end
  def self.flush_timing_logg
    if logger.present?
      @@timings.each do |label, time|
        logger.warn "#{label}: #{time}s"
      end
      true
    end
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
    time_logged :send_stream do

      time_logged :flatten_payloads do
        payloads.flatten!
      end

      # retain valid payloads only
      time_logged :validate_payload do
        payloads.reject!{ |p| !(p.is_a?(APNS::Payload) && p.valid?) }
      end

      return if (payloads.nil? || payloads.count < 1)

      # loop through each payloads
      payloads.each do |payload|
        retry_delay = 2

        # !ToDo! do a better job by using a select to poll the socket for a possible response from apple to inform us about an error in the sent payload
        #
        begin
          time_logged :connect do
            if @@ssl[stream].nil?
              @@sock[stream], @@ssl[stream] = self.push_connection(stream)
            end
          end
          ssl_payload = time_logged :make_payload do
            payload.to_ssl
          end
          time_logged :write do
            @@ssl[stream].write(ssl_payload);
          end
          time_logged :flush do
            @@ssl[stream].flush
          end
        rescue PemPathError, PemFileError => e
          raise e
        rescue
          @@ssl[stream].close; @@sock[stream].close
          @@ssl[stream] = nil; @@sock[stream] = nil # cleanup

          retry_delay *= 2
          if retry_delay <= 8
            logger.warn "Failed to write payload, sleeping for #{retry_delay}!" if logger.present?
            time_logged :sleep do
              sleep retry_delay
            end
            retry
          else
            raise
          end
        end # begin block

      end # each payloads
    end
    flush_timing_logg
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

    context, sock, ssl = nil, nil, nil
    context = time_logged :connect__ssl_context do
      self.ssl_context(stream)
    end
    sock = time_logged :connect__tcp_socket_new do
      TCPSocket.new(aps_host, aps_port)
    end
    ssl = time_logged :connect__ssl_socket_new do
      OpenSSL::SSL::SSLSocket.new(sock, context)
    end
    time_logged :connect__ssl_connect do
      ssl.connect
    end

    return sock, ssl
  end

  def self.push_connection(stream = :_global)
    self.connect_to(self.host, self.port, stream)
  end

  def self.feedback_connection(stream = :_global)
    self.connect_to(self.feedback_host, self.feedback_port, stream)
  end

end
