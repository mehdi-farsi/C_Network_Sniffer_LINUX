#ifndef		__COLOR_H__
# define	__COLOR_H__

#include	<stdio.h>

#define		CLEARSCREEN()		printf("\033[H\033[2J")
#define		INITCOLOR(color)	printf("\033[%sm", color)
#define		RED_COLOR		"31"
#define		GREEN_COLOR		"32"
#define		YELLOW_COLOR		"33"
#define		BLUE_COLOR		"34"
#define		ZERO_COLOR		"0"

#endif		/* __COLOR_H__ */
