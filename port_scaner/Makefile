# The compiler to use
CC = gcc

# Compiler flags: 
# -Wall, -Werror, -Wextra, -pedantic are strict warning flags (Betty style)
# -g adds debugging information
CFLAGS = -Wall -Werror -Wextra -pedantic -g

# The name of our final executable file
NAME = port_scanner

# A list of all our .c source files
SRC = main.c \
      parse_proc_net.c \
      find_process_by_inode.c \
      check_high_interest.c \
      set_risk_label.c \
      compare_ports.c \
      strtolower.c

# This dynamically replaces the .c extension with .o for object files
OBJ = $(SRC:.c=.o)

# The default rule that runs when you just type 'make'
all: $(NAME)

# Rule to link all the .o object files into the final executable
$(NAME): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(NAME)

# Rule to clean up intermediate .o files to keep the directory tidy
clean:
	rm -f $(OBJ)

# Rule to aggressively clean up .o files AND the executable file
fclean: clean
	rm -f $(NAME)
	rm -f ports_report.txt

# Rule to force a complete re-compilation from scratch
re: fclean all

# Tells make that these are rules, not actual files named 'clean' or 'all'
.PHONY: all clean fclean re
