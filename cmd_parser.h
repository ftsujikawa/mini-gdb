/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2021 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

#ifndef YY_CMDYY_CMD_PARSER_H_INCLUDED
# define YY_CMDYY_CMD_PARSER_H_INCLUDED
/* Debug traces.  */
#ifndef CMDYYDEBUG
# if defined YYDEBUG
#if YYDEBUG
#   define CMDYYDEBUG 1
#  else
#   define CMDYYDEBUG 0
#  endif
# else /* ! defined YYDEBUG */
#  define CMDYYDEBUG 0
# endif /* ! defined YYDEBUG */
#endif  /* ! defined CMDYYDEBUG */
#if CMDYYDEBUG
extern int cmdyydebug;
#endif

/* Token kinds.  */
#ifndef CMDYYTOKENTYPE
# define CMDYYTOKENTYPE
  enum cmdyytokentype
  {
    CMDYYEMPTY = -2,
    CMDYYEOF = 0,                  /* "end of file"  */
    CMDYYerror = 256,              /* error  */
    CMDYYUNDEF = 257,              /* "invalid token"  */
    T_EOL = 258,                   /* T_EOL  */
    T_WORD = 259,                  /* T_WORD  */
    T_REST = 260,                  /* T_REST  */
    T_RUN = 261,                   /* T_RUN  */
    T_C = 262,                     /* T_C  */
    T_S = 263,                     /* T_S  */
    T_SI = 264,                    /* T_SI  */
    T_N = 265,                     /* T_N  */
    T_UP = 266,                    /* T_UP  */
    T_KILL = 267,                  /* T_KILL  */
    T_REGS = 268,                  /* T_REGS  */
    T_SYMS = 269,                  /* T_SYMS  */
    T_TB = 270,                    /* T_TB  */
    T_L = 271,                     /* T_L  */
    T_LIST = 272,                  /* T_LIST  */
    T_DIS = 273,                   /* T_DIS  */
    T_B = 274,                     /* T_B  */
    T_BREAK = 275,                 /* T_BREAK  */
    T_DEL = 276,                   /* T_DEL  */
    T_DELETE = 277,                /* T_DELETE  */
    T_SHOW = 278,                  /* T_SHOW  */
    T_DBG = 279,                   /* T_DBG  */
    T_LINES = 280,                 /* T_LINES  */
    T_X = 281,                     /* T_X  */
    T_P = 282,                     /* T_P  */
    T_PRINT = 283,                 /* T_PRINT  */
    T_SET = 284,                   /* T_SET  */
    T_WATCH = 285,                 /* T_WATCH  */
    T_HELP = 286,                  /* T_HELP  */
    T_Q = 287                      /* T_Q  */
  };
  typedef enum cmdyytokentype cmdyytoken_kind_t;
#endif

/* Value type.  */
#if ! defined CMDYYSTYPE && ! defined CMDYYSTYPE_IS_DECLARED
union CMDYYSTYPE
{
#line 23 "cmd_parser.y"

    char *str;

#line 108 "cmd_parser.h"

};
typedef union CMDYYSTYPE CMDYYSTYPE;
# define CMDYYSTYPE_IS_TRIVIAL 1
# define CMDYYSTYPE_IS_DECLARED 1
#endif


extern CMDYYSTYPE cmdyylval;


int cmdyyparse (void);


#endif /* !YY_CMDYY_CMD_PARSER_H_INCLUDED  */
