# General tasks MakeFile

SHELL := /bin/bash
sendFilesFromLocalToVM:
	scp -r * ns@192.168.51.112:/home/ns/

sendFilesFromVMToContainers:
	for container in "alice" "bob" "trudy"; do \
		lxc file push -r root/root.crt *.py $$container/* $${container}1/root/ ; \
	done 

updateRootCA:
	for container in "alice1" "bob1" "trudy1"; do \
		lxc exec $$container -- cp root.crt /usr/local/share/ca-certificates/ ; \
		lxc exec $$container -- sudo update-ca-certificates ; \
	done

clean:
	for container in "alice1" "bob1" "trudy1"; do \
		lxc exec $$container -- bash -c "rm -rf /root/{__pycache__/,alice/,bob/,*.crt,*.csr,*.sign,*.txt,*.py,*.pem}"; \
		lxc exec $$container -- bash -c "rm -rf /usr/local/share/ca-certificates/root.crt"; \
	done
	rm -rf alice/ bob/ trudy/ root/ *.py *.crt /usr/local/share/ca-certificates/root.crt *.txt Makefile