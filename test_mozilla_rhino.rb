#!/usr/bin/env ruby

require 'json'
require 'base64'

# Load ysoserial payloads
data = JSON.parse(File.read('../ysoserial_payloads.json'))
payload_bytes = Base64.decode64(data['none']['MozillaRhino1']['bytes'])

puts "Testing MozillaRhino1 payload..."
puts "Total size: #{payload_bytes.length} bytes"

begin
  # Try to parse with rex-java
  io = StringIO.new(payload_bytes)
  stream = Rex::Java::Serialization::Model::Stream.new
  stream.decode(io)

  puts "✅ Ruby rex-java successfully parsed MozillaRhino1"
  puts "Contents count: #{stream.contents.length}"
  puts "References count: #{stream.references.length}"

  # Show content around where Go failed
  stream.contents.each_with_index do |content, i|
    puts "Content[#{i}]: #{content.class.name.split('::').last}"
  end

rescue => e
  puts "❌ Ruby rex-java failed: #{e.message}"
  puts "Error class: #{e.class}"
end
