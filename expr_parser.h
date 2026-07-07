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

#ifndef YY_EXPRYY_EXPR_PARSER_H_INCLUDED
# define YY_EXPRYY_EXPR_PARSER_H_INCLUDED
/* Debug traces.  */
#ifndef EXPRYYDEBUG
# if defined YYDEBUG
#if YYDEBUG
#   define EXPRYYDEBUG 1
#  else
#   define EXPRYYDEBUG 0
#  endif
# else /* ! defined YYDEBUG */
#  define EXPRYYDEBUG 0
# endif /* ! defined YYDEBUG */
#endif  /* ! defined EXPRYYDEBUG */
#if EXPRYYDEBUG
extern int expryydebug;
#endif

/* Token kinds.  */
#ifndef EXPRYYTOKENTYPE
# define EXPRYYTOKENTYPE
  enum expryytokentype
  {
    EXPRYYEMPTY = -2,
    EXPRYYEOF = 0,                 /* "end of file"  */
    EXPRYYerror = 256,             /* error  */
    EXPRYYUNDEF = 257,             /* "invalid token"  */
    T_EOL = 258,                   /* T_EOL  */
    T_NUM = 259,                   /* T_NUM  */
    T_IDENT = 260,                 /* T_IDENT  */
    T_REG = 261,                   /* T_REG  */
    T_SHL = 262,                   /* T_SHL  */
    T_SHR = 263,                   /* T_SHR  */
    T_LE = 264,                    /* T_LE  */
    T_GE = 265,                    /* T_GE  */
    T_EQ = 266,                    /* T_EQ  */
    T_NE = 267,                    /* T_NE  */
    T_LAND = 268,                  /* T_LAND  */
    T_LOR = 269,                   /* T_LOR  */
    T_ARROW = 270,                 /* T_ARROW  */
    UPLUS = 271,                   /* UPLUS  */
    UMINUS = 272,                  /* UMINUS  */
    DEREF = 273,                   /* DEREF  */
    ADDR = 274                     /* ADDR  */
  };
  typedef enum expryytokentype expryytoken_kind_t;
#endif

/* Value type.  */
#if ! defined EXPRYYSTYPE && ! defined EXPRYYSTYPE_IS_DECLARED
union EXPRYYSTYPE
{
#line 21 "expr_parser.y"

    unsigned long u64;
    char *str;
    expr_ast_t *ast;

#line 97 "expr_parser.h"

};
typedef union EXPRYYSTYPE EXPRYYSTYPE;
# define EXPRYYSTYPE_IS_TRIVIAL 1
# define EXPRYYSTYPE_IS_DECLARED 1
#endif


extern EXPRYYSTYPE expryylval;


int expryyparse (void);


#endif /* !YY_EXPRYY_EXPR_PARSER_H_INCLUDED  */
