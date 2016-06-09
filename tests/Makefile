all:
	for i in $$(find * -maxdepth 0 -type d); do \
		make -C $$i ; \
	done

clean:
	for i in $$(find * -maxdepth 0 -type d); do \
		make -C $$i clean; \
	done