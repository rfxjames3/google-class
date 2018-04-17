class ApacheLogAnalyzer

  def initialize
    @total_hits_by_ip = Hash.new(0)
    @total_hits_per_url = Hash.new(0)
    @secret_hits_by_ip = Hash.new(0)
    @error_count = 0
  end

  def analyze(file_name)

    octet = /\d{,2}|1\d{2}|2[0-4]\d|25[0-5]/
      ip_regex = /^#{octet}\.#{octet}\.#{octet}\.#{octet}/
      url_regex = /[a-zA-Z0-9]+.html/

    File.open(file_name).each do |line|


     url_string = url_regex.match(line).to_s
     m = nil
     k = nil
     error = false
     secret = false

     if line.include?("secret")
       
       m = ip_regex.match(line)
       secret = true
     end

     if line.include?("404")
       
       k = ip_regex.match(line)
       error = true
     end

	 ip = m.to_s if m != nil   
    ip = k.to_s if k != nil   

    url = url_string

	secret = true if m != nil
	error = true if k != nil
	
    count_hits(ip, url, secret, error) 
  
  end   

  print_hits

end  

private

def count_hits(ip, url, secret, error)

  @total_hits_by_ip[ip] += 1
  @total_hits_per_url[url] += 1
  @secret_hits_by_ip[ip] += 1 unless secret == false
  @error_count +=1 unless error == false
end

   def print_hits
    print_string = 'IP: %s, Total Hits: %s, Secret Hits: %s'
    @total_hits_by_ip.sort.each do |ip, total_hits|
    secret_hits = @secret_hits_by_ip[ip]
    puts sprintf(print_string, ip, total_hits, secret_hits)
    end
    url_print_string = 'URL: %s, Number of Hits: %s'
    @total_hits_per_url.sort.each do |url, url_hits|
    puts sprintf(url_print_string, url, url_hits)
    end
    puts sprintf('Total Errors: %s', @error_count)
  end

end

def usage
  puts "No log files passed, please pass at least one log file.\n\n"
  puts "USAGE: #{$PROGRAM_NAME} file1 [file2 ...]\n\n"
  puts "Analyzes apache2 log files for unique IP addresses and unique URLs."
end

def main
  if ARGV.empty?
    usage
    exit(1)
  end

  ARGV.each do |file_name|
    log_analyzer = ApacheLogAnalyzer.new
    log_analyzer.analyze(file_name)
  end
end

if __FILE__ == $PROGRAM_NAME
  main
end

