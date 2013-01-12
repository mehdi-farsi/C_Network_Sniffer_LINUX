NAME	=	network_sniffer
SRCS	=	main.c		\
		tools.c		\
		show_data.c

OBJS	=	$(SRCS:.c=.o)
CC	=	gcc -o
CFLAGS	=	-W -Wall
RM	=	rm -rf

$(NAME)	:	$(OBJS)
		$(CC) $(NAME) -I./ $(CFLAGS) $(OBJS)

all	:	$(NAME)

clean	:
		$(RM) $(OBJS)

fclean	:	clean
		$(RM) $(NAME)

re	:	fclean all
