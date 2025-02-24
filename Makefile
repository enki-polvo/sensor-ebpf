# List of project directories (assumes all projects are under events/)
PROJECTS := $(wildcard events/*)

# ANSI color codes for highlighting messages
WHITE_BOLD := \033[1;37m
CYAN_BOLD := \033[1;36m
GREEN_BOLD := \033[1;32m
RESET := \033[0m

# The default target builds all projects.
.PHONY: all clean $(PROJECTS)
all: $(PROJECTS)
	@echo "$(GREEN_BOLD)All projects built successfully!$(RESET)"

# For each project directory, run go generate and build the binary.
# The output binary will be named after the directory, with a .out suffix.
$(PROJECTS):
	@echo "$(GREEN_BOLD)==== Building project: $@ ====$(RESET)"
	@cd $@ && \
	    echo "$(WHITE_BOLD)Running bpftool to generate vmlinux.h in $@...$(RESET)" && \
	    bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h && \
	    echo "$(WHITE_BOLD)Running go generate in $@...$(RESET)" && \
	    go generate && \
	    echo "$(WHITE_BOLD)Running go build in $@...$(RESET)" && \
	    go build -o $(notdir $@).out && \
	    echo "$(CYAN_BOLD)Built binary: $(notdir $@).out$(RESET)"
	@echo "$(GREEN_BOLD)==== Finished building: $@ ====$(RESET)"



# Clean up binaries and generated files matching *_bpfeb.* and *_bpfel.*
clean:
	@echo "$(GREEN_BOLD)==== Cleaning up generated binaries and artifacts ====$(RESET)"
	@for d in $(PROJECTS); do \
	    echo "$(WHITE_BOLD)Cleaning $$d...$(RESET)"; \
	    rm -f $$d/*.out $$d/*_bpfeb.* $$d/*_bpfel.*; \
	done
	@echo "$(GREEN_BOLD)==== Clean complete ====$(RESET)"

