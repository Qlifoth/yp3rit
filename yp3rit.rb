#! /usr/bin/ruby

require 'open-uri'
require 'nokogiri'
require 'shodan'

print ("\n\n   ___________________________________________________________________________________________   \n   |||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||   \n   |~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|   \n   |~~~~~~~~~~~~~~~~~~~~~~##~~##~~#####~~~~####~~~#####~~~######~~######~~~~~~~~~~~~~~~~~~~~~|   \n   |~~~~~~~~######~~##~~~~~####~~~##~~##~~#~~~##~~##~~##~~~~##~~~~##~~~~~~##~~~~######~~~~~~~|   \n   |#####~~~~~~~~~~~~~~~~~~~##~~~~#####~~~~~###~~~#####~~~~~##~~~~#####~~~~~~~~~~~~~~~~~#####|   \n   |~~~~~~~~######~~##~~~~~~##~~~~##~~~~~~#~~~##~~##~~##~~~~##~~~~##~~~~~~##~~~~######~~~~~~~|   \n   |~~~~~~~~~~~~~~~~~~~~~~~~##~~~~##~~~~~~~####~~~##~~##~~~~##~~~~######~~~~~~~~~~~~~~~~~~~~~|   \n   |~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|   \n   |||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||   \n   '''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''   \n\n")
$lin="================================================================================"
	def whiche
		print ("\n\n  You may try to search it by masscan or nmap \n (m) masscan \n (n) nmap  \n (s) Shodan \n\n >")
		prog= gets().chomp()
		if prog	== "masscan" || prog == "m" then
			masscan
		elsif prog == "nmap" || prog == "n"
			nmap
		elsif prog == "shodan" || prog == "s"
			shodan
		end
	end

	def shodan
		print ("\n"+$lin+"\n")
		print ($lin+"\n\n")
		print ("\n\n\n\n\n\n\n Ok, you can try to test \n (f) Test honypot ip's file \n (h) Test target host on honypot \n (s) Shodan search \n\n")
		print (" --> ")
		way = gets().chomp()
		if way == "f" then
			honyf
		elsif way == "t"
			honyt
		elsif way == "s"
			shod
		elsif way == "b"
			which

		end
	end

		def honyf
			key= ("WA9rlYKJpojwY8DUeLwbz9sESG5m8YRc");		
			print ("\n FILE > ")
			input= gets().chomp()
			print ("\n OUTPUT > ")
			oput= gets().chomp()
			print ("\n RISK > ")
			risk= gets().chomp()
			file = File.open("#{input}")
			file.each {|line| x = Nokogiri::HTML(open("https://api.shodan.io/labs/honeyscore/#{line.chomp}?key=#{key}")).xpath("//text()").text.chomp
				if x<=risk then
					ofile = File.new("#{oput}", 'a')			
					print ("#{line.chomp} "+" -- #{x}\n")
					ofile.print ("#{line.chomp}\n")
					ofile.close
				end
			}
		end

		def honyt
	
			STDOUT.flush;
			print ("\n RHOST > ");
			ip= gets().chomp();
			print ("\n RISK > ")
			risk= gets().chomp()
			key= ("WA9rlYKJpojwY8DUeLwbz9sESG5m8YRc");
			doc = Nokogiri::HTML(open("https://api.shodan.io/labs/honeyscore/#{ip}?key=#{key}"));
			x = (doc.xpath("//text()").text)
			if x<=risk then
				print ("\n  #{ip.chomp} "+" -- #{x}\n")
			end
	
		end

		def shod
			api = Shodan::Shodan.new('WA9rlYKJpojwY8DUeLwbz9sESG5m8YRc')
			print ("Query > ")
			STDOUT.flush
			qry	= gets.chomp
			result = api.search(qry)
			result['matches'].each{ |host|
			        puts host['ip_str']
			}
		end

	def masscan
		print ("\n"+$lin+"\n\n")
		puts $lin
		print ("\n\n  MASSCAN \n\n   So now you will chose port and ip diapason file, \n  put the nomber of the port (usally 3306) \n  and stsic link to the file.\n\n FILE > ")
		file = gets().chomp()
		print (" --> "+file+"\n\n RPORT > ")
		port = gets().chomp()
		print (" --> "+port+" \n\nNow you may choose other options for masscan, or just press enter\n\n OPTIONS > ")
		opt = gets().chomp()
		print (" --> "+opt+"\n\n Put name of output file \n\n OUTPUT > ")
		outf = gets().chomp()
		print (" --> "+outf+"\n\n\n Ok, now just type run, and it good to go \n or operation will start all over \n\n RUN > ")
		run = gets().chomp()
		if run == "run" || run == "RUN" then
			system ("masscan #{opt} -p#{port} --randomize-hosts -Pn -n -sS --connection-timeout 20  --open -iL #{file} | grep -E -o '(([0-9]{1,3}[\.]){3}[0-9]{1,3})' > #{outf}")
			host_count = 0 
				File.open("#{outf}").each do |line|
				host_count += 1
				outf << line
			end
			puts ("==============================")
			print ("\n\n        !  #{host_count} hosts\n\n")
			puts ("==============================")
		
		else masscan
		end
	end

	def nmap
	def which
		print ("\n"+$lin+"\n\n")
		print ("\n\n\nWhat aru you going to test: \n\n  (1) FTP \n  (2) SSH \n  (3) SSL \n  (4) VULN \n  (5) MySQL \n  (u) Unusual-port \n     on port put number of ports \n  (t) Scan target without ports \n (b) Back   \n\n  > ")
		prog= gets().chomp()
		print ("\n\n  RHOST > ")
		@rhosts= gets().chomp()
		print ("  rhosts => "+@rhosts+"\n\n  RPORTS > ")
		@rports= gets().chomp()
		print ("  rport => "+@rports+"\n\n  OPTIONS > ")
		@opts= gets().chomp()
		print ("  options => "+@opts+"\n\n")
		if prog	== "1" || prog == "ftp" then
			ftp
		elsif prog == "2" || prog == "ssh"
			ssh
		elsif prog == "3" || prog == "ssl"
			ssl
		elsif prog == "4" || prog == "vuln"
			vuln
		elsif prog == "5" || prog == "mysql"
			mysql
		elsif prog == "u" || prog == "unusual"
			system ("nmap --top-ports #{@rports} #{opt} --script unusual-port #{host}")
			which		
		elsif prog == "t" || prog == "target"
			system ("nmap #{@opts} #{@rhosts}")
			which
		elsif prog == "b" || prog == "back"
			whiche
#				system ("nmap --top-ports #{@rports} #{opt} --script unusual-port #{host}")
#				system ("nmap -p#{@rports} #{@opts} #{@rhosts}")
		end
	end
			def ftp
				print ("\n (1) Finde FTP on unusual-port \n (2) Scan target ftp \n (3) Firewall-bypass with FTP helper \n (4) CVE-2010-1938 - OPIE off-by-one stack overflow \n (5) Stack-based buffer overflow in the \n      ProFTPD server 1.3.2rc3 - 1.3.3b \n (6) Tests ProFTPD 1.3.3c for backdoor \n (7) Tests vsFTPd 2.3.4 for backdoor \n (0) Exit \n (s) Back \n\n")
				print ("\n\n  RUN > ")
				runs= gets().chomp()		
				
					if runs == "1" then
				
						system ("nmap #{@opts} --script unusual-port #{@rhosts}")
						ftp
		
					elsif runs == "2"
		
						system ("nmap -p#{@rports} -sC -sV -Pn -PE #{@opts} #{@rhosts}")
						ftp
					elsif runs =="3"
		
						system ("nmap --script firewall-bypass --script-args firewall-bypass.helper=ftp, firewall-bypass.targetport=#{@rports} #{@opts} #{@rhosts}")
						ftp
		
					elsif runs =="4"
		
						system ("nmap -p#{@rports} -Pn -PE -sV #{@opts} --script=ftp-libopie #{@rhosts}")
						ftp
		
					elsif runs =="5"
		
						system ("nmap -p#{@rports} --script ftp-vuln-cve2010-4221 #{@opts} #{@rhosts}")
						ftp
		
					elsif runs =="6"
		
						system ("nmap -p#{@rports} --script ftp-proftpd-backdoor #{@opts} #{@rhosts}")
						ftp
		
					elsif runs =="7"
		
						system ("nmap -p#{@rports} --script ftp-vsftpd-backdoor #{@opts} #{@rhosts}")
						ftp
		
					elsif runs =="6"
		
						system ("nmap -p#{@rports} --script ftp-brute  #{@rhosts}")				
						ftp
		
					elsif runs == "start" || runs == "s"
		
						which
					
					elsif runs == "exit" || runs == "0"	
			
						abort
			
					else ftp
					
					end
			end
		
			def ssh
				print ("\n (1)  Check SSH Protocol Version 1 \n (2) Report number of algorithms (for encryption, compression, etc.) of SSH2 server \n (3) Returns authentication methods \n (4) Show the target server's key fingerprint  \n (5) Run remote command on server \n (6) Brute \n (0) Exit \n (s) Back  \n\n")
				print ("\n\n  RUN > ")
				runs= gets().chomp()		
				
					if runs == "1" then
			
						system ("nmap -p#{@rports} -sC -sV #{@opts} #{@rhosts}")				
						ssh
		
					elsif runs == "2"
	
						system ("nmap -p#{@rports} #{@opts} --script ssh2-enum-algos #{@rhosts}")
						
						ssh
					elsif runs =="3"
						print ("\n\n  USER >")
						user= gets().chomp()
						print ("  username => "+user+"\n\n")
						system ("nmap -p#{@rports} #{@opts} --script ssh-auth-methods --script-args=\"ssh.user=#{user}\" #{@rhosts}")
						ssh
		
					elsif runs =="4"
						print("\n\n full: The entire key, not just the fingerprint. \n bubble: Bubble Babble output, \n visual: Visual ASCII art representation. \n all : All of the above.")
						print ("\n\n  HKEY >")
						hkey= gets().chomp()
						print ("  hostkey => "+hkey+"\n\n")
						system ("nmap host -p#{@rports} #{@opts} --script ssh-hostkey --script-args ssh_hostkey=#{hkey}  #{@rhosts}")
						ssh
		
					elsif runs =="5"
						print ("\n\n  USER > ")
						user= gets().chomp()
						print ("  username => "+user+"\n\n")
						print ("\n  PASS > ")
						pass= gets().chomp()
						print ("  password => "+pass+"\n\n")
						print ("\n COMMAND > ")
						comnd= gets().chomp()
						print ("  password => "+comnd+"\n\n")
						system ("nmap -p#{@rports} #{@opts} -v -d --script=ssh-run --datadir=./ --script-args=\"ssh-run.cmd=#{comnd} /, ssh-run.username=#{user}, ssh-run.password=#{pass}\" #{@rhosts}")
						ssh
		
					elsif runs =="6"
		
						system ("nmap -p#{@rports} #{@opts} --script ssh-brute --script-args userdb=users.lst,passdb=pass.lst --script-args ssh-brute.timeout=4s #{@rhosts}")
						ssh
		
					elsif runs == "start" || runs == "s"
		
						which
					
					elsif runs == "exit" || run == "0"	
			
						abort
			
					else ssh
					
					end
			end
		
		
			def ssl
		
				print ("\n (1) Scan target\n (2) CVE-2014-0224 \n      File SSL CSS-injection\n (3) SSL cert-intaddr IP.4  \n (4) Retrieves host's time and date from its TLS ServerHello response \n (5) CVE 2015-4000  \n     Weak ephemeral Diffie-Hellman parameter detection for SSL/TLS services \n (0) Exit \n (s) Back  \n\n")
		
				if runs == "1" then
				
					system ("nmap #{@opts} --script unusual-port #{@rhosts}")
					ssl
	
				elsif runs == "1"
	
					system ("nmap -p#{@rports} -sV -sC #{@opts} #{@rhosts}")
					ssl
				elsif runs =="2"
	
					system ("nmap -p#{@rports} --script ssl-ccs-injection #{@opts} #{@rhosts}")
					ssl
	
				elsif runs =="3"
	
					system ("nmap -p#{@rports} --script ssl-cert-intaddr #{@opts} #{@rhosts}")
					ssl
	
				elsif runs =="4"
	
					system ("nmap -p#{@rports} --script=ssl-date #{@opts} #{@rhosts}")
					ssl
	
				elsif runs =="5"
	
					system ("nmap -p#{@rports} --script ssl-dh-params #{@opts} #{@rhosts}")
					ssl
	
				elsif runs =="7"
	
					system ("nmap -p#{@rports} --script ftp-vsftpd-backdoor #{@opts} #{@rhosts}")
					ssl
	
				elsif runs =="6"
	
					system ("nmap -p#{@rports} --script ftp-brute  #{@rhosts}")				
					ssl
	
				elsif runs == "start" || runs == "s"
	
					which
				
				elsif runs == "exit" || run == "0"	
		
					abort
		
				else ssl
				
				end
			end
	
		
			def vuln
				print ("\n (1) Use Nmap-Vulners \n (2) Use Vulscan all \n (3) scipvuldb.csv \n (4) exploitdb.csv \n (5) securitytracker.csv \n (0) Exit \n (s) Back   \n\n")
				print ("\n\n  RUN > ")
				runs= gets().chomp()		
				
					if runs == "1" then
				
						system ("nmap -p#{@rports} --script nmap-vulners -sV  #{@opts} #{@rhosts}")
						vuln
					elsif runs =="2"
						system ("nmap -p#{@rports} --script vulscan -sV #{@opts} #{@rhosts}")
						vuln
					elsif runs =="3"
						system ("nmap -p#{@rports} --script vulscan --script-args vulscandb=scipvuldb.csv -sV  #{@opts} #{@rhosts}")
						vuln
					elsif runs =="4"
						system ("nmap -p#{@rports} --script vulscan --script-args vulscandb=exploitdb.csv -sV  #{@opts} #{@rhosts}")
						vuln
					elsif runs =="5"
						system ("nmap -p#{@rports} --script vulscan --script-args vulscandb=securitytracker.csv -sV  #{@opts} #{@rhosts}")
						vuln
					elsif runs == "start" || runs == "s"
						which
					elsif runs == "exit" || runs == "0"	
						abort
					else vuln
					end
			end
	
	
			def mysql
				print ("\n (1) Get info \n (2) List all users on server \n (3) Perform valid-user enumeration \n (4) Check server with an empty password for root or anonymous \n (5) Attempt to list all databases on server \n (6) Dumps the password hashes from an MySQL server \n (7) Show all whichiables on server \n (8) Audits MySQL database server security configuration \n     against parts of the CIS MySQL v1.0.2 benchmark \n     (the engine can be used for other MySQL audits \n     by creating appropriate audit files). \n (9) Run query against database \n (10) Attempt to bypass authentication exploiting CVE2012-2122 \n (11) Perform password guessing against MySQL \n (0) Exit \n (s) Back  \n\n")
				print ("\n\n  RUN > ")
				runs= gets().chomp()		
				
					if runs == "1" then
				
						system ("nmap -p#{@rports} -sC -sV  #{@opts} #{@rhosts}")
						mysql
		
					elsif runs =="2"
		
						system ("nmap -p#{@rports} -sV --script=mysql-users #{@opts} #{@rhosts}")
						mysql
		
					elsif runs =="3"
		
						system ("nmap -p#{@rports} --script=mysql-enum  #{@opts} #{@rhosts}")
						mysql
		
					elsif runs =="4"
		
						system ("nmap -p#{@rports} -sV --script=mysql-empty-password  #{@opts} #{@rhosts}")
						mysql
		
					elsif runs =="5"
		
						system ("nmap -p#{@rports} -sV --script=mysql-databases #{@opts} #{@rhosts}")
						mysql
		
					elsif runs =="6"
		
						print ("\n\n  USER >")
						user= gets().chomp()
						print ("  username => "+user+"\n")
						print ("\n  PASS >")
						pass= gets().chomp()
						print ("  password => "+pass+"\n\n")
						system ("nmap -p#{@rports} #{@rhosts} #{@opts} --script mysql-dump-hashes --script-args='username=#{user},password=#{pass}'")
						mysql
					elsif runs =="7"
		
						system ("nmap -p#{@rports} -sV --script=mysql-whichiables #{@opts} #{@rhosts}")
						mysql
					elsif runs =="8"
		
		
						print ("\n\n  USER >")
						user= gets().chomp()
						print ("  username => "+user+"\n")
						print ("\n  PASS >")
						pass= gets().chomp()
						print ("  password => "+pass+"\n\n")
						print ("\n nselib / data / mysql-cis.audit ")
						print ("\n  FILE >")
						file= gets().chomp()
						print ("  audit.filename => "+pass+"\n\n")
						system ("nmap -p#{@rports} --script mysql-audit --script-args \"mysql-audit.username='#{user}',  mysql-audit.password='#{pass}',mysql-audit.filename='#{file}'\" #{@opts} #{@rhosts}")
						mysql
		
					elsif runs =="9"
		
						print ("\n\n  USER >")
						user= gets().chomp()
						print ("  username => "+user+"\n")
						print ("\n  PASS >")
						pass= gets().chomp()
						print ("  password => "+pass+"\n\n")
						print ("\n  QUERY >")
						query= gets().chomp()
						print ("  query => "+query+"\n\n")
						system ("nmap -p#{@rports} #{@rhosts} #{@opts} --script mysql-query --script-args='query=\"#{query}\"[,username=#{user},password=#{pass}]'")
						mysql
		
					elsif runs =="10"
		
						system ("nmap -p#{@rports} #{@opts} --script mysql-vuln-cve2012-2122 #{@rhosts}")
						mysql
		
					elsif runs =="11"
		
						system ("NMap -p#{@rports} #{@opts} --script=mysql-brute #{@rhosts}")
						mysql
		
					elsif runs == "start" || runs == "s"
		
						which
					
					elsif runs == "exit" || runs == "0"	
			
						abort
			
					else mysql
					
					end
			end
	
		which
	end

whiche
