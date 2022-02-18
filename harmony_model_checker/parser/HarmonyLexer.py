# Generated from Harmony.g4 by ANTLR 4.9.3
from antlr4 import *
from io import StringIO
import sys
if sys.version_info[1] > 5:
    from typing import TextIO
else:
    from typing.io import TextIO


from .custom_denter import ModifiedDenterHelper
from .HarmonyParser import HarmonyParser



def serializedATN():
    with StringIO() as buf:
        buf.write("\3\u608b\ua72a\u8133\ub9ed\u417c\u3be7\u7786\u5964\2u")
        buf.write("\u0365\b\1\4\2\t\2\4\3\t\3\4\4\t\4\4\5\t\5\4\6\t\6\4\7")
        buf.write("\t\7\4\b\t\b\4\t\t\t\4\n\t\n\4\13\t\13\4\f\t\f\4\r\t\r")
        buf.write("\4\16\t\16\4\17\t\17\4\20\t\20\4\21\t\21\4\22\t\22\4\23")
        buf.write("\t\23\4\24\t\24\4\25\t\25\4\26\t\26\4\27\t\27\4\30\t\30")
        buf.write("\4\31\t\31\4\32\t\32\4\33\t\33\4\34\t\34\4\35\t\35\4\36")
        buf.write("\t\36\4\37\t\37\4 \t \4!\t!\4\"\t\"\4#\t#\4$\t$\4%\t%")
        buf.write("\4&\t&\4\'\t\'\4(\t(\4)\t)\4*\t*\4+\t+\4,\t,\4-\t-\4.")
        buf.write("\t.\4/\t/\4\60\t\60\4\61\t\61\4\62\t\62\4\63\t\63\4\64")
        buf.write("\t\64\4\65\t\65\4\66\t\66\4\67\t\67\48\t8\49\t9\4:\t:")
        buf.write("\4;\t;\4<\t<\4=\t=\4>\t>\4?\t?\4@\t@\4A\tA\4B\tB\4C\t")
        buf.write("C\4D\tD\4E\tE\4F\tF\4G\tG\4H\tH\4I\tI\4J\tJ\4K\tK\4L\t")
        buf.write("L\4M\tM\4N\tN\4O\tO\4P\tP\4Q\tQ\4R\tR\4S\tS\4T\tT\4U\t")
        buf.write("U\4V\tV\4W\tW\4X\tX\4Y\tY\4Z\tZ\4[\t[\4\\\t\\\4]\t]\4")
        buf.write("^\t^\4_\t_\4`\t`\4a\ta\4b\tb\4c\tc\4d\td\4e\te\4f\tf\4")
        buf.write("g\tg\4h\th\4i\ti\4j\tj\4k\tk\4l\tl\4m\tm\4n\tn\4o\to\4")
        buf.write("p\tp\4q\tq\4r\tr\4s\ts\4t\tt\4u\tu\4v\tv\4w\tw\4x\tx\4")
        buf.write("y\ty\4z\tz\4{\t{\3\2\3\2\3\2\3\2\3\3\3\3\3\3\3\4\3\4\3")
        buf.write("\4\3\5\3\5\3\6\3\6\3\7\3\7\3\b\3\b\3\t\3\t\3\n\3\n\3\n")
        buf.write("\3\13\3\13\3\f\3\f\3\r\3\r\3\r\3\r\3\16\3\16\3\16\3\17")
        buf.write("\3\17\3\17\3\20\3\20\3\20\3\21\3\21\3\21\3\22\3\22\3\22")
        buf.write("\3\23\3\23\3\24\3\24\3\24\3\25\3\25\3\26\3\26\3\26\3\27")
        buf.write("\3\27\3\30\3\30\3\30\3\30\3\31\3\31\3\31\3\31\3\31\3\31")
        buf.write("\3\31\3\31\3\32\3\32\3\32\3\32\3\32\3\32\3\32\3\32\3\32")
        buf.write("\3\32\3\32\3\33\3\33\3\33\3\33\3\33\3\33\3\33\3\33\3\33")
        buf.write("\3\33\3\33\3\33\3\34\3\34\3\34\3\34\3\34\3\34\3\34\3\34")
        buf.write("\3\34\3\35\3\35\3\35\3\35\3\35\3\35\3\35\3\35\3\36\3\36")
        buf.write("\3\36\3\36\3\37\3\37\3\37\3\37\3 \3 \3 \3 \3!\3!\3!\3")
        buf.write("!\3\"\3\"\3\"\3\"\3#\3#\3#\3#\3$\3$\3$\3$\3$\3%\3%\3%")
        buf.write("\3%\3%\3&\3&\3&\3&\3&\3&\3&\3\'\3\'\3\'\3\'\3(\3(\3(\3")
        buf.write("(\3(\3)\3)\3)\3)\3*\3*\3*\3*\3+\3+\3+\3,\3,\3,\3-\3-\3")
        buf.write("-\3.\3.\3.\3/\3/\3/\3\60\3\60\3\60\3\61\3\61\3\61\3\62")
        buf.write("\3\62\3\62\3\62\3\63\3\63\3\63\3\64\3\64\3\64\3\64\3\64")
        buf.write("\3\65\3\65\3\65\3\65\3\66\3\66\3\66\3\66\3\67\5\67\u01ca")
        buf.write("\n\67\3\67\3\67\7\67\u01ce\n\67\f\67\16\67\u01d1\13\67")
        buf.write("\3\67\7\67\u01d4\n\67\f\67\16\67\u01d7\13\67\5\67\u01d9")
        buf.write("\n\67\3\67\3\67\38\68\u01de\n8\r8\168\u01df\38\68\u01e3")
        buf.write("\n8\r8\168\u01e4\38\38\38\58\u01ea\n8\38\38\39\39\79\u01f0")
        buf.write("\n9\f9\169\u01f3\139\39\39\39\39\79\u01f9\n9\f9\169\u01fc")
        buf.write("\139\59\u01fe\n9\3:\3:\3;\3;\3;\3<\3<\3<\3=\3=\3>\3>\3")
        buf.write("?\3?\3?\3@\3@\3A\3A\3A\3A\3A\3A\3A\3B\3B\3B\3B\3B\3B\3")
        buf.write("C\3C\3C\3C\3C\3D\3D\3D\3E\3E\3E\3E\3E\3E\3E\3E\3E\3E\3")
        buf.write("E\3E\3F\3F\3F\3G\3G\3G\3G\3G\3H\3H\3H\3H\3H\3I\3I\3I\3")
        buf.write("I\3I\3I\3I\3J\3J\3K\3K\3K\3K\3L\3L\3M\3M\3M\3M\3M\3M\3")
        buf.write("N\3N\3N\3N\3N\3N\3O\3O\3O\3O\3O\3O\3O\3P\3P\3P\3P\3Q\3")
        buf.write("Q\3Q\3Q\3Q\3R\3R\3R\3R\3R\3S\3S\3S\3S\3T\3T\3T\3T\3T\3")
        buf.write("T\3U\3U\3U\3U\3U\3U\3U\3U\3U\3U\3V\3V\3V\3W\3W\3W\3W\3")
        buf.write("W\3W\3W\3W\3W\3W\3W\3X\3X\3X\3X\3X\3Y\3Y\3Y\3Y\3Z\3Z\3")
        buf.write("Z\3[\3[\3[\3[\3[\3\\\3\\\3\\\3\\\3\\\3]\3]\3^\3^\3^\3")
        buf.write("^\3^\3^\3_\3_\3_\3_\3`\3`\3`\3`\3`\3`\3`\3a\3a\3a\3a\3")
        buf.write("a\3a\3b\3b\3c\3c\3c\3c\3c\3c\3d\3d\3d\3d\3d\3e\3e\3f\3")
        buf.write("f\3f\3f\3f\3g\3g\3g\3g\3g\3g\3g\3g\3g\3g\3g\3h\3h\3h\3")
        buf.write("h\3h\3h\3h\3h\3h\5h\u02e8\nh\3i\3i\3i\3i\3i\3i\3i\3i\3")
        buf.write("j\6j\u02f3\nj\rj\16j\u02f4\3j\3j\3j\5j\u02fa\nj\3k\3k")
        buf.write("\7k\u02fe\nk\fk\16k\u0301\13k\3l\3l\3l\5l\u0306\nl\3m")
        buf.write("\3m\3m\3m\6m\u030c\nm\rm\16m\u030d\3n\3n\3o\3o\3o\3p\3")
        buf.write("p\3p\3q\3q\3q\3r\3r\3r\3s\3s\3s\3t\3t\3t\3u\3u\3v\3v\5")
        buf.write("v\u0328\nv\3w\3w\3w\7w\u032d\nw\fw\16w\u0330\13w\3w\3")
        buf.write("w\3w\3w\7w\u0336\nw\fw\16w\u0339\13w\3w\5w\u033c\nw\3")
        buf.write("x\3x\3x\3x\3x\7x\u0343\nx\fx\16x\u0346\13x\3x\3x\3x\3")
        buf.write("x\3x\3x\3x\3x\7x\u0350\nx\fx\16x\u0353\13x\3x\3x\3x\5")
        buf.write("x\u0358\nx\3y\3y\5y\u035c\ny\3z\3z\3{\3{\3{\3{\5{\u0364")
        buf.write("\n{\5\u01f1\u0344\u0351\2|\3\3\5\4\7\5\t\6\13\7\r\b\17")
        buf.write("\t\21\n\23\13\25\f\27\r\31\16\33\17\35\20\37\21!\22#\23")
        buf.write("%\24\'\25)\26+\27-\30/\31\61\32\63\33\65\34\67\359\36")
        buf.write(";\37= ?!A\"C#E$G%I&K\'M(O)Q*S+U,W-Y.[/]\60_\61a\62c\63")
        buf.write("e\64g\65i\66k\67m8o9q\2s:u;w<y={>}?\177@\u0081A\u0083")
        buf.write("B\u0085C\u0087D\u0089E\u008bF\u008dG\u008fH\u0091I\u0093")
        buf.write("J\u0095K\u0097L\u0099M\u009bN\u009dO\u009fP\u00a1Q\u00a3")
        buf.write("R\u00a5S\u00a7T\u00a9U\u00abV\u00adW\u00afX\u00b1Y\u00b3")
        buf.write("Z\u00b5[\u00b7\\\u00b9]\u00bb^\u00bd_\u00bf`\u00c1a\u00c3")
        buf.write("b\u00c5c\u00c7d\u00c9e\u00cbf\u00cdg\u00cfh\u00d1i\u00d3")
        buf.write("j\u00d5k\u00d7l\u00d9m\u00db\2\u00ddn\u00dfo\u00e1p\u00e3")
        buf.write("q\u00e5r\u00e7s\u00e9t\u00ebu\u00ed\2\u00ef\2\u00f1\2")
        buf.write("\u00f3\2\u00f5\2\3\2\13\4\2\f\f\16\17\3\2\62;\5\2C\\a")
        buf.write("ac|\6\2\62;C\\aac|\3\2\60\60\5\2\62;CHch\6\2\f\f\16\17")
        buf.write("))^^\6\2\f\f\16\17$$^^\3\2^^\2\u037a\2\3\3\2\2\2\2\5\3")
        buf.write("\2\2\2\2\7\3\2\2\2\2\t\3\2\2\2\2\13\3\2\2\2\2\r\3\2\2")
        buf.write("\2\2\17\3\2\2\2\2\21\3\2\2\2\2\23\3\2\2\2\2\25\3\2\2\2")
        buf.write("\2\27\3\2\2\2\2\31\3\2\2\2\2\33\3\2\2\2\2\35\3\2\2\2\2")
        buf.write("\37\3\2\2\2\2!\3\2\2\2\2#\3\2\2\2\2%\3\2\2\2\2\'\3\2\2")
        buf.write("\2\2)\3\2\2\2\2+\3\2\2\2\2-\3\2\2\2\2/\3\2\2\2\2\61\3")
        buf.write("\2\2\2\2\63\3\2\2\2\2\65\3\2\2\2\2\67\3\2\2\2\29\3\2\2")
        buf.write("\2\2;\3\2\2\2\2=\3\2\2\2\2?\3\2\2\2\2A\3\2\2\2\2C\3\2")
        buf.write("\2\2\2E\3\2\2\2\2G\3\2\2\2\2I\3\2\2\2\2K\3\2\2\2\2M\3")
        buf.write("\2\2\2\2O\3\2\2\2\2Q\3\2\2\2\2S\3\2\2\2\2U\3\2\2\2\2W")
        buf.write("\3\2\2\2\2Y\3\2\2\2\2[\3\2\2\2\2]\3\2\2\2\2_\3\2\2\2\2")
        buf.write("a\3\2\2\2\2c\3\2\2\2\2e\3\2\2\2\2g\3\2\2\2\2i\3\2\2\2")
        buf.write("\2k\3\2\2\2\2m\3\2\2\2\2o\3\2\2\2\2s\3\2\2\2\2u\3\2\2")
        buf.write("\2\2w\3\2\2\2\2y\3\2\2\2\2{\3\2\2\2\2}\3\2\2\2\2\177\3")
        buf.write("\2\2\2\2\u0081\3\2\2\2\2\u0083\3\2\2\2\2\u0085\3\2\2\2")
        buf.write("\2\u0087\3\2\2\2\2\u0089\3\2\2\2\2\u008b\3\2\2\2\2\u008d")
        buf.write("\3\2\2\2\2\u008f\3\2\2\2\2\u0091\3\2\2\2\2\u0093\3\2\2")
        buf.write("\2\2\u0095\3\2\2\2\2\u0097\3\2\2\2\2\u0099\3\2\2\2\2\u009b")
        buf.write("\3\2\2\2\2\u009d\3\2\2\2\2\u009f\3\2\2\2\2\u00a1\3\2\2")
        buf.write("\2\2\u00a3\3\2\2\2\2\u00a5\3\2\2\2\2\u00a7\3\2\2\2\2\u00a9")
        buf.write("\3\2\2\2\2\u00ab\3\2\2\2\2\u00ad\3\2\2\2\2\u00af\3\2\2")
        buf.write("\2\2\u00b1\3\2\2\2\2\u00b3\3\2\2\2\2\u00b5\3\2\2\2\2\u00b7")
        buf.write("\3\2\2\2\2\u00b9\3\2\2\2\2\u00bb\3\2\2\2\2\u00bd\3\2\2")
        buf.write("\2\2\u00bf\3\2\2\2\2\u00c1\3\2\2\2\2\u00c3\3\2\2\2\2\u00c5")
        buf.write("\3\2\2\2\2\u00c7\3\2\2\2\2\u00c9\3\2\2\2\2\u00cb\3\2\2")
        buf.write("\2\2\u00cd\3\2\2\2\2\u00cf\3\2\2\2\2\u00d1\3\2\2\2\2\u00d3")
        buf.write("\3\2\2\2\2\u00d5\3\2\2\2\2\u00d7\3\2\2\2\2\u00d9\3\2\2")
        buf.write("\2\2\u00dd\3\2\2\2\2\u00df\3\2\2\2\2\u00e1\3\2\2\2\2\u00e3")
        buf.write("\3\2\2\2\2\u00e5\3\2\2\2\2\u00e7\3\2\2\2\2\u00e9\3\2\2")
        buf.write("\2\2\u00eb\3\2\2\2\3\u00f7\3\2\2\2\5\u00fb\3\2\2\2\7\u00fe")
        buf.write("\3\2\2\2\t\u0101\3\2\2\2\13\u0103\3\2\2\2\r\u0105\3\2")
        buf.write("\2\2\17\u0107\3\2\2\2\21\u0109\3\2\2\2\23\u010b\3\2\2")
        buf.write("\2\25\u010e\3\2\2\2\27\u0110\3\2\2\2\31\u0112\3\2\2\2")
        buf.write("\33\u0116\3\2\2\2\35\u0119\3\2\2\2\37\u011c\3\2\2\2!\u011f")
        buf.write("\3\2\2\2#\u0122\3\2\2\2%\u0125\3\2\2\2\'\u0127\3\2\2\2")
        buf.write(")\u012a\3\2\2\2+\u012c\3\2\2\2-\u012f\3\2\2\2/\u0131\3")
        buf.write("\2\2\2\61\u0135\3\2\2\2\63\u013d\3\2\2\2\65\u0148\3\2")
        buf.write("\2\2\67\u0154\3\2\2\29\u015d\3\2\2\2;\u0165\3\2\2\2=\u0169")
        buf.write("\3\2\2\2?\u016d\3\2\2\2A\u0171\3\2\2\2C\u0175\3\2\2\2")
        buf.write("E\u0179\3\2\2\2G\u017d\3\2\2\2I\u0182\3\2\2\2K\u0187\3")
        buf.write("\2\2\2M\u018e\3\2\2\2O\u0192\3\2\2\2Q\u0197\3\2\2\2S\u019b")
        buf.write("\3\2\2\2U\u019f\3\2\2\2W\u01a2\3\2\2\2Y\u01a5\3\2\2\2")
        buf.write("[\u01a8\3\2\2\2]\u01ab\3\2\2\2_\u01ae\3\2\2\2a\u01b1\3")
        buf.write("\2\2\2c\u01b4\3\2\2\2e\u01b8\3\2\2\2g\u01bb\3\2\2\2i\u01c0")
        buf.write("\3\2\2\2k\u01c4\3\2\2\2m\u01c9\3\2\2\2o\u01e9\3\2\2\2")
        buf.write("q\u01fd\3\2\2\2s\u01ff\3\2\2\2u\u0201\3\2\2\2w\u0204\3")
        buf.write("\2\2\2y\u0207\3\2\2\2{\u0209\3\2\2\2}\u020b\3\2\2\2\177")
        buf.write("\u020e\3\2\2\2\u0081\u0210\3\2\2\2\u0083\u0217\3\2\2\2")
        buf.write("\u0085\u021d\3\2\2\2\u0087\u0222\3\2\2\2\u0089\u0225\3")
        buf.write("\2\2\2\u008b\u0231\3\2\2\2\u008d\u0234\3\2\2\2\u008f\u0239")
        buf.write("\3\2\2\2\u0091\u023e\3\2\2\2\u0093\u0245\3\2\2\2\u0095")
        buf.write("\u0247\3\2\2\2\u0097\u024b\3\2\2\2\u0099\u024d\3\2\2\2")
        buf.write("\u009b\u0253\3\2\2\2\u009d\u0259\3\2\2\2\u009f\u0260\3")
        buf.write("\2\2\2\u00a1\u0264\3\2\2\2\u00a3\u0269\3\2\2\2\u00a5\u026e")
        buf.write("\3\2\2\2\u00a7\u0272\3\2\2\2\u00a9\u0278\3\2\2\2\u00ab")
        buf.write("\u0282\3\2\2\2\u00ad\u0285\3\2\2\2\u00af\u0290\3\2\2\2")
        buf.write("\u00b1\u0295\3\2\2\2\u00b3\u0299\3\2\2\2\u00b5\u029c\3")
        buf.write("\2\2\2\u00b7\u02a1\3\2\2\2\u00b9\u02a6\3\2\2\2\u00bb\u02a8")
        buf.write("\3\2\2\2\u00bd\u02ae\3\2\2\2\u00bf\u02b2\3\2\2\2\u00c1")
        buf.write("\u02b9\3\2\2\2\u00c3\u02bf\3\2\2\2\u00c5\u02c1\3\2\2\2")
        buf.write("\u00c7\u02c7\3\2\2\2\u00c9\u02cc\3\2\2\2\u00cb\u02ce\3")
        buf.write("\2\2\2\u00cd\u02d3\3\2\2\2\u00cf\u02e7\3\2\2\2\u00d1\u02e9")
        buf.write("\3\2\2\2\u00d3\u02f9\3\2\2\2\u00d5\u02fb\3\2\2\2\u00d7")
        buf.write("\u0302\3\2\2\2\u00d9\u0307\3\2\2\2\u00db\u030f\3\2\2\2")
        buf.write("\u00dd\u0311\3\2\2\2\u00df\u0314\3\2\2\2\u00e1\u0317\3")
        buf.write("\2\2\2\u00e3\u031a\3\2\2\2\u00e5\u031d\3\2\2\2\u00e7\u0320")
        buf.write("\3\2\2\2\u00e9\u0323\3\2\2\2\u00eb\u0327\3\2\2\2\u00ed")
        buf.write("\u033b\3\2\2\2\u00ef\u0357\3\2\2\2\u00f1\u035b\3\2\2\2")
        buf.write("\u00f3\u035d\3\2\2\2\u00f5\u0363\3\2\2\2\u00f7\u00f8\7")
        buf.write("c\2\2\u00f8\u00f9\7p\2\2\u00f9\u00fa\7f\2\2\u00fa\4\3")
        buf.write("\2\2\2\u00fb\u00fc\7q\2\2\u00fc\u00fd\7t\2\2\u00fd\6\3")
        buf.write("\2\2\2\u00fe\u00ff\7?\2\2\u00ff\u0100\7@\2\2\u0100\b\3")
        buf.write("\2\2\2\u0101\u0102\7(\2\2\u0102\n\3\2\2\2\u0103\u0104")
        buf.write("\7~\2\2\u0104\f\3\2\2\2\u0105\u0106\7`\2\2\u0106\16\3")
        buf.write("\2\2\2\u0107\u0108\7/\2\2\u0108\20\3\2\2\2\u0109\u010a")
        buf.write("\7-\2\2\u010a\22\3\2\2\2\u010b\u010c\7\61\2\2\u010c\u010d")
        buf.write("\7\61\2\2\u010d\24\3\2\2\2\u010e\u010f\7\61\2\2\u010f")
        buf.write("\26\3\2\2\2\u0110\u0111\7\'\2\2\u0111\30\3\2\2\2\u0112")
        buf.write("\u0113\7o\2\2\u0113\u0114\7q\2\2\u0114\u0115\7f\2\2\u0115")
        buf.write("\32\3\2\2\2\u0116\u0117\7,\2\2\u0117\u0118\7,\2\2\u0118")
        buf.write("\34\3\2\2\2\u0119\u011a\7>\2\2\u011a\u011b\7>\2\2\u011b")
        buf.write("\36\3\2\2\2\u011c\u011d\7@\2\2\u011d\u011e\7@\2\2\u011e")
        buf.write(" \3\2\2\2\u011f\u0120\7?\2\2\u0120\u0121\7?\2\2\u0121")
        buf.write("\"\3\2\2\2\u0122\u0123\7#\2\2\u0123\u0124\7?\2\2\u0124")
        buf.write("$\3\2\2\2\u0125\u0126\7>\2\2\u0126&\3\2\2\2\u0127\u0128")
        buf.write("\7>\2\2\u0128\u0129\7?\2\2\u0129(\3\2\2\2\u012a\u012b")
        buf.write("\7@\2\2\u012b*\3\2\2\2\u012c\u012d\7@\2\2\u012d\u012e")
        buf.write("\7?\2\2\u012e,\3\2\2\2\u012f\u0130\7\u0080\2\2\u0130.")
        buf.write("\3\2\2\2\u0131\u0132\7c\2\2\u0132\u0133\7d\2\2\u0133\u0134")
        buf.write("\7u\2\2\u0134\60\3\2\2\2\u0135\u0136\7c\2\2\u0136\u0137")
        buf.write("\7v\2\2\u0137\u0138\7N\2\2\u0138\u0139\7c\2\2\u0139\u013a")
        buf.write("\7d\2\2\u013a\u013b\7g\2\2\u013b\u013c\7n\2\2\u013c\62")
        buf.write("\3\2\2\2\u013d\u013e\7e\2\2\u013e\u013f\7q\2\2\u013f\u0140")
        buf.write("\7w\2\2\u0140\u0141\7p\2\2\u0141\u0142\7v\2\2\u0142\u0143")
        buf.write("\7N\2\2\u0143\u0144\7c\2\2\u0144\u0145\7d\2\2\u0145\u0146")
        buf.write("\7g\2\2\u0146\u0147\7n\2\2\u0147\64\3\2\2\2\u0148\u0149")
        buf.write("\7i\2\2\u0149\u014a\7g\2\2\u014a\u014b\7v\2\2\u014b\u014c")
        buf.write("\7a\2\2\u014c\u014d\7e\2\2\u014d\u014e\7q\2\2\u014e\u014f")
        buf.write("\7p\2\2\u014f\u0150\7v\2\2\u0150\u0151\7g\2\2\u0151\u0152")
        buf.write("\7z\2\2\u0152\u0153\7v\2\2\u0153\66\3\2\2\2\u0154\u0155")
        buf.write("\7e\2\2\u0155\u0156\7q\2\2\u0156\u0157\7p\2\2\u0157\u0158")
        buf.write("\7v\2\2\u0158\u0159\7g\2\2\u0159\u015a\7z\2\2\u015a\u015b")
        buf.write("\7v\2\2\u015b\u015c\7u\2\2\u015c8\3\2\2\2\u015d\u015e")
        buf.write("\7k\2\2\u015e\u015f\7u\2\2\u015f\u0160\7G\2\2\u0160\u0161")
        buf.write("\7o\2\2\u0161\u0162\7r\2\2\u0162\u0163\7v\2\2\u0163\u0164")
        buf.write("\7{\2\2\u0164:\3\2\2\2\u0165\u0166\7o\2\2\u0166\u0167")
        buf.write("\7k\2\2\u0167\u0168\7p\2\2\u0168<\3\2\2\2\u0169\u016a")
        buf.write("\7o\2\2\u016a\u016b\7c\2\2\u016b\u016c\7z\2\2\u016c>\3")
        buf.write("\2\2\2\u016d\u016e\7n\2\2\u016e\u016f\7g\2\2\u016f\u0170")
        buf.write("\7p\2\2\u0170@\3\2\2\2\u0171\u0172\7u\2\2\u0172\u0173")
        buf.write("\7v\2\2\u0173\u0174\7t\2\2\u0174B\3\2\2\2\u0175\u0176")
        buf.write("\7c\2\2\u0176\u0177\7p\2\2\u0177\u0178\7{\2\2\u0178D\3")
        buf.write("\2\2\2\u0179\u017a\7c\2\2\u017a\u017b\7n\2\2\u017b\u017c")
        buf.write("\7n\2\2\u017cF\3\2\2\2\u017d\u017e\7m\2\2\u017e\u017f")
        buf.write("\7g\2\2\u017f\u0180\7{\2\2\u0180\u0181\7u\2\2\u0181H\3")
        buf.write("\2\2\2\u0182\u0183\7j\2\2\u0183\u0184\7c\2\2\u0184\u0185")
        buf.write("\7u\2\2\u0185\u0186\7j\2\2\u0186J\3\2\2\2\u0187\u0188")
        buf.write("\7e\2\2\u0188\u0189\7j\2\2\u0189\u018a\7q\2\2\u018a\u018b")
        buf.write("\7q\2\2\u018b\u018c\7u\2\2\u018c\u018d\7g\2\2\u018dL\3")
        buf.write("\2\2\2\u018e\u018f\7g\2\2\u018f\u0190\7p\2\2\u0190\u0191")
        buf.write("\7f\2\2\u0191N\3\2\2\2\u0192\u0193\7c\2\2\u0193\u0194")
        buf.write("\7p\2\2\u0194\u0195\7f\2\2\u0195\u0196\7?\2\2\u0196P\3")
        buf.write("\2\2\2\u0197\u0198\7q\2\2\u0198\u0199\7t\2\2\u0199\u019a")
        buf.write("\7?\2\2\u019aR\3\2\2\2\u019b\u019c\7?\2\2\u019c\u019d")
        buf.write("\7@\2\2\u019d\u019e\7?\2\2\u019eT\3\2\2\2\u019f\u01a0")
        buf.write("\7(\2\2\u01a0\u01a1\7?\2\2\u01a1V\3\2\2\2\u01a2\u01a3")
        buf.write("\7~\2\2\u01a3\u01a4\7?\2\2\u01a4X\3\2\2\2\u01a5\u01a6")
        buf.write("\7`\2\2\u01a6\u01a7\7?\2\2\u01a7Z\3\2\2\2\u01a8\u01a9")
        buf.write("\7/\2\2\u01a9\u01aa\7?\2\2\u01aa\\\3\2\2\2\u01ab\u01ac")
        buf.write("\7-\2\2\u01ac\u01ad\7?\2\2\u01ad^\3\2\2\2\u01ae\u01af")
        buf.write("\7,\2\2\u01af\u01b0\7?\2\2\u01b0`\3\2\2\2\u01b1\u01b2")
        buf.write("\7\61\2\2\u01b2\u01b3\7?\2\2\u01b3b\3\2\2\2\u01b4\u01b5")
        buf.write("\7\61\2\2\u01b5\u01b6\7\61\2\2\u01b6\u01b7\7?\2\2\u01b7")
        buf.write("d\3\2\2\2\u01b8\u01b9\7\'\2\2\u01b9\u01ba\7?\2\2\u01ba")
        buf.write("f\3\2\2\2\u01bb\u01bc\7o\2\2\u01bc\u01bd\7q\2\2\u01bd")
        buf.write("\u01be\7f\2\2\u01be\u01bf\7?\2\2\u01bfh\3\2\2\2\u01c0")
        buf.write("\u01c1\7,\2\2\u01c1\u01c2\7,\2\2\u01c2\u01c3\7?\2\2\u01c3")
        buf.write("j\3\2\2\2\u01c4\u01c5\7@\2\2\u01c5\u01c6\7@\2\2\u01c6")
        buf.write("\u01c7\7?\2\2\u01c7l\3\2\2\2\u01c8\u01ca\7\17\2\2\u01c9")
        buf.write("\u01c8\3\2\2\2\u01c9\u01ca\3\2\2\2\u01ca\u01cb\3\2\2\2")
        buf.write("\u01cb\u01d8\7\f\2\2\u01cc\u01ce\7\"\2\2\u01cd\u01cc\3")
        buf.write("\2\2\2\u01ce\u01d1\3\2\2\2\u01cf\u01cd\3\2\2\2\u01cf\u01d0")
        buf.write("\3\2\2\2\u01d0\u01d9\3\2\2\2\u01d1\u01cf\3\2\2\2\u01d2")
        buf.write("\u01d4\7\13\2\2\u01d3\u01d2\3\2\2\2\u01d4\u01d7\3\2\2")
        buf.write("\2\u01d5\u01d3\3\2\2\2\u01d5\u01d6\3\2\2\2\u01d6\u01d9")
        buf.write("\3\2\2\2\u01d7\u01d5\3\2\2\2\u01d8\u01cf\3\2\2\2\u01d8")
        buf.write("\u01d5\3\2\2\2\u01d9\u01da\3\2\2\2\u01da\u01db\b\67\2")
        buf.write("\2\u01dbn\3\2\2\2\u01dc\u01de\7\"\2\2\u01dd\u01dc\3\2")
        buf.write("\2\2\u01de\u01df\3\2\2\2\u01df\u01dd\3\2\2\2\u01df\u01e0")
        buf.write("\3\2\2\2\u01e0\u01ea\3\2\2\2\u01e1\u01e3\7\13\2\2\u01e2")
        buf.write("\u01e1\3\2\2\2\u01e3\u01e4\3\2\2\2\u01e4\u01e2\3\2\2\2")
        buf.write("\u01e4\u01e5\3\2\2\2\u01e5\u01ea\3\2\2\2\u01e6\u01e7\7")
        buf.write("^\2\2\u01e7\u01ea\5m\67\2\u01e8\u01ea\5q9\2\u01e9\u01dd")
        buf.write("\3\2\2\2\u01e9\u01e2\3\2\2\2\u01e9\u01e6\3\2\2\2\u01e9")
        buf.write("\u01e8\3\2\2\2\u01ea\u01eb\3\2\2\2\u01eb\u01ec\b8\3\2")
        buf.write("\u01ecp\3\2\2\2\u01ed\u01f1\5u;\2\u01ee\u01f0\13\2\2\2")
        buf.write("\u01ef\u01ee\3\2\2\2\u01f0\u01f3\3\2\2\2\u01f1\u01f2\3")
        buf.write("\2\2\2\u01f1\u01ef\3\2\2\2\u01f2\u01f4\3\2\2\2\u01f3\u01f1")
        buf.write("\3\2\2\2\u01f4\u01f5\5w<\2\u01f5\u01fe\3\2\2\2\u01f6\u01fa")
        buf.write("\5s:\2\u01f7\u01f9\n\2\2\2\u01f8\u01f7\3\2\2\2\u01f9\u01fc")
        buf.write("\3\2\2\2\u01fa\u01f8\3\2\2\2\u01fa\u01fb\3\2\2\2\u01fb")
        buf.write("\u01fe\3\2\2\2\u01fc\u01fa\3\2\2\2\u01fd\u01ed\3\2\2\2")
        buf.write("\u01fd\u01f6\3\2\2\2\u01fer\3\2\2\2\u01ff\u0200\7%\2\2")
        buf.write("\u0200t\3\2\2\2\u0201\u0202\7*\2\2\u0202\u0203\7,\2\2")
        buf.write("\u0203v\3\2\2\2\u0204\u0205\7,\2\2\u0205\u0206\7+\2\2")
        buf.write("\u0206x\3\2\2\2\u0207\u0208\7#\2\2\u0208z\3\2\2\2\u0209")
        buf.write("\u020a\7,\2\2\u020a|\3\2\2\2\u020b\u020c\7c\2\2\u020c")
        buf.write("\u020d\7u\2\2\u020d~\3\2\2\2\u020e\u020f\7\60\2\2\u020f")
        buf.write("\u0080\3\2\2\2\u0210\u0211\7k\2\2\u0211\u0212\7o\2\2\u0212")
        buf.write("\u0213\7r\2\2\u0213\u0214\7q\2\2\u0214\u0215\7t\2\2\u0215")
        buf.write("\u0216\7v\2\2\u0216\u0082\3\2\2\2\u0217\u0218\7r\2\2\u0218")
        buf.write("\u0219\7t\2\2\u0219\u021a\7k\2\2\u021a\u021b\7p\2\2\u021b")
        buf.write("\u021c\7v\2\2\u021c\u0084\3\2\2\2\u021d\u021e\7h\2\2\u021e")
        buf.write("\u021f\7t\2\2\u021f\u0220\7q\2\2\u0220\u0221\7o\2\2\u0221")
        buf.write("\u0086\3\2\2\2\u0222\u0223\7\60\2\2\u0223\u0224\7\60\2")
        buf.write("\2\u0224\u0088\3\2\2\2\u0225\u0226\7u\2\2\u0226\u0227")
        buf.write("\7g\2\2\u0227\u0228\7v\2\2\u0228\u0229\7k\2\2\u0229\u022a")
        buf.write("\7p\2\2\u022a\u022b\7v\2\2\u022b\u022c\7n\2\2\u022c\u022d")
        buf.write("\7g\2\2\u022d\u022e\7x\2\2\u022e\u022f\7g\2\2\u022f\u0230")
        buf.write("\7n\2\2\u0230\u008a\3\2\2\2\u0231\u0232\7/\2\2\u0232\u0233")
        buf.write("\7@\2\2\u0233\u008c\3\2\2\2\u0234\u0235\7u\2\2\u0235\u0236")
        buf.write("\7c\2\2\u0236\u0237\7x\2\2\u0237\u0238\7g\2\2\u0238\u008e")
        buf.write("\3\2\2\2\u0239\u023a\7u\2\2\u023a\u023b\7v\2\2\u023b\u023c")
        buf.write("\7q\2\2\u023c\u023d\7r\2\2\u023d\u0090\3\2\2\2\u023e\u023f")
        buf.write("\7n\2\2\u023f\u0240\7c\2\2\u0240\u0241\7o\2\2\u0241\u0242")
        buf.write("\7d\2\2\u0242\u0243\7f\2\2\u0243\u0244\7c\2\2\u0244\u0092")
        buf.write("\3\2\2\2\u0245\u0246\7A\2\2\u0246\u0094\3\2\2\2\u0247")
        buf.write("\u0248\7p\2\2\u0248\u0249\7q\2\2\u0249\u024a\7v\2\2\u024a")
        buf.write("\u0096\3\2\2\2\u024b\u024c\7.\2\2\u024c\u0098\3\2\2\2")
        buf.write("\u024d\u024e\7e\2\2\u024e\u024f\7q\2\2\u024f\u0250\7p")
        buf.write("\2\2\u0250\u0251\7u\2\2\u0251\u0252\7v\2\2\u0252\u009a")
        buf.write("\3\2\2\2\u0253\u0254\7c\2\2\u0254\u0255\7y\2\2\u0255\u0256")
        buf.write("\7c\2\2\u0256\u0257\7k\2\2\u0257\u0258\7v\2\2\u0258\u009c")
        buf.write("\3\2\2\2\u0259\u025a\7c\2\2\u025a\u025b\7u\2\2\u025b\u025c")
        buf.write("\7u\2\2\u025c\u025d\7g\2\2\u025d\u025e\7t\2\2\u025e\u025f")
        buf.write("\7v\2\2\u025f\u009e\3\2\2\2\u0260\u0261\7x\2\2\u0261\u0262")
        buf.write("\7c\2\2\u0262\u0263\7t\2\2\u0263\u00a0\3\2\2\2\u0264\u0265")
        buf.write("\7v\2\2\u0265\u0266\7t\2\2\u0266\u0267\7c\2\2\u0267\u0268")
        buf.write("\7r\2\2\u0268\u00a2\3\2\2\2\u0269\u026a\7r\2\2\u026a\u026b")
        buf.write("\7c\2\2\u026b\u026c\7u\2\2\u026c\u026d\7u\2\2\u026d\u00a4")
        buf.write("\3\2\2\2\u026e\u026f\7f\2\2\u026f\u0270\7g\2\2\u0270\u0271")
        buf.write("\7n\2\2\u0271\u00a6\3\2\2\2\u0272\u0273\7u\2\2\u0273\u0274")
        buf.write("\7r\2\2\u0274\u0275\7c\2\2\u0275\u0276\7y\2\2\u0276\u0277")
        buf.write("\7p\2\2\u0277\u00a8\3\2\2\2\u0278\u0279\7k\2\2\u0279\u027a")
        buf.write("\7p\2\2\u027a\u027b\7x\2\2\u027b\u027c\7c\2\2\u027c\u027d")
        buf.write("\7t\2\2\u027d\u027e\7k\2\2\u027e\u027f\7c\2\2\u027f\u0280")
        buf.write("\7p\2\2\u0280\u0281\7v\2\2\u0281\u00aa\3\2\2\2\u0282\u0283")
        buf.write("\7i\2\2\u0283\u0284\7q\2\2\u0284\u00ac\3\2\2\2\u0285\u0286")
        buf.write("\7u\2\2\u0286\u0287\7g\2\2\u0287\u0288\7s\2\2\u0288\u0289")
        buf.write("\7w\2\2\u0289\u028a\7g\2\2\u028a\u028b\7p\2\2\u028b\u028c")
        buf.write("\7v\2\2\u028c\u028d\7k\2\2\u028d\u028e\7c\2\2\u028e\u028f")
        buf.write("\7n\2\2\u028f\u00ae\3\2\2\2\u0290\u0291\7y\2\2\u0291\u0292")
        buf.write("\7j\2\2\u0292\u0293\7g\2\2\u0293\u0294\7p\2\2\u0294\u00b0")
        buf.write("\3\2\2\2\u0295\u0296\7n\2\2\u0296\u0297\7g\2\2\u0297\u0298")
        buf.write("\7v\2\2\u0298\u00b2\3\2\2\2\u0299\u029a\7k\2\2\u029a\u029b")
        buf.write("\7h\2\2\u029b\u00b4\3\2\2\2\u029c\u029d\7g\2\2\u029d\u029e")
        buf.write("\7n\2\2\u029e\u029f\7k\2\2\u029f\u02a0\7h\2\2\u02a0\u00b6")
        buf.write("\3\2\2\2\u02a1\u02a2\7g\2\2\u02a2\u02a3\7n\2\2\u02a3\u02a4")
        buf.write("\7u\2\2\u02a4\u02a5\7g\2\2\u02a5\u00b8\3\2\2\2\u02a6\u02a7")
        buf.write("\7B\2\2\u02a7\u00ba\3\2\2\2\u02a8\u02a9\7y\2\2\u02a9\u02aa")
        buf.write("\7j\2\2\u02aa\u02ab\7k\2\2\u02ab\u02ac\7n\2\2\u02ac\u02ad")
        buf.write("\7g\2\2\u02ad\u00bc\3\2\2\2\u02ae\u02af\7f\2\2\u02af\u02b0")
        buf.write("\7g\2\2\u02b0\u02b1\7h\2\2\u02b1\u00be\3\2\2\2\u02b2\u02b3")
        buf.write("\7g\2\2\u02b3\u02b4\7z\2\2\u02b4\u02b5\7k\2\2\u02b5\u02b6")
        buf.write("\7u\2\2\u02b6\u02b7\7v\2\2\u02b7\u02b8\7u\2\2\u02b8\u00c0")
        buf.write("\3\2\2\2\u02b9\u02ba\7y\2\2\u02ba\u02bb\7j\2\2\u02bb\u02bc")
        buf.write("\7g\2\2\u02bc\u02bd\7t\2\2\u02bd\u02be\7g\2\2\u02be\u00c2")
        buf.write("\3\2\2\2\u02bf\u02c0\7?\2\2\u02c0\u00c4\3\2\2\2\u02c1")
        buf.write("\u02c2\7h\2\2\u02c2\u02c3\7q\2\2\u02c3\u02c4\7t\2\2\u02c4")
        buf.write("\u02c5\3\2\2\2\u02c5\u02c6\bc\4\2\u02c6\u00c6\3\2\2\2")
        buf.write("\u02c7\u02c8\7k\2\2\u02c8\u02c9\7p\2\2\u02c9\u02ca\3\2")
        buf.write("\2\2\u02ca\u02cb\bd\5\2\u02cb\u00c8\3\2\2\2\u02cc\u02cd")
        buf.write("\7<\2\2\u02cd\u00ca\3\2\2\2\u02ce\u02cf\7P\2\2\u02cf\u02d0")
        buf.write("\7q\2\2\u02d0\u02d1\7p\2\2\u02d1\u02d2\7g\2\2\u02d2\u00cc")
        buf.write("\3\2\2\2\u02d3\u02d4\7c\2\2\u02d4\u02d5\7v\2\2\u02d5\u02d6")
        buf.write("\7q\2\2\u02d6\u02d7\7o\2\2\u02d7\u02d8\7k\2\2\u02d8\u02d9")
        buf.write("\7e\2\2\u02d9\u02da\7c\2\2\u02da\u02db\7n\2\2\u02db\u02dc")
        buf.write("\7n\2\2\u02dc\u02dd\7{\2\2\u02dd\u00ce\3\2\2\2\u02de\u02df")
        buf.write("\7H\2\2\u02df\u02e0\7c\2\2\u02e0\u02e1\7n\2\2\u02e1\u02e2")
        buf.write("\7u\2\2\u02e2\u02e8\7g\2\2\u02e3\u02e4\7V\2\2\u02e4\u02e5")
        buf.write("\7t\2\2\u02e5\u02e6\7w\2\2\u02e6\u02e8\7g\2\2\u02e7\u02de")
        buf.write("\3\2\2\2\u02e7\u02e3\3\2\2\2\u02e8\u00d0\3\2\2\2\u02e9")
        buf.write("\u02ea\7g\2\2\u02ea\u02eb\7v\2\2\u02eb\u02ec\7g\2\2\u02ec")
        buf.write("\u02ed\7t\2\2\u02ed\u02ee\7p\2\2\u02ee\u02ef\7c\2\2\u02ef")
        buf.write("\u02f0\7n\2\2\u02f0\u00d2\3\2\2\2\u02f1\u02f3\t\3\2\2")
        buf.write("\u02f2\u02f1\3\2\2\2\u02f3\u02f4\3\2\2\2\u02f4\u02f2\3")
        buf.write("\2\2\2\u02f4\u02f5\3\2\2\2\u02f5\u02fa\3\2\2\2\u02f6\u02f7")
        buf.write("\7k\2\2\u02f7\u02f8\7p\2\2\u02f8\u02fa\7h\2\2\u02f9\u02f2")
        buf.write("\3\2\2\2\u02f9\u02f6\3\2\2\2\u02fa\u00d4\3\2\2\2\u02fb")
        buf.write("\u02ff\t\4\2\2\u02fc\u02fe\t\5\2\2\u02fd\u02fc\3\2\2\2")
        buf.write("\u02fe\u0301\3\2\2\2\u02ff\u02fd\3\2\2\2\u02ff\u0300\3")
        buf.write("\2\2\2\u0300\u00d6\3\2\2\2\u0301\u02ff\3\2\2\2\u0302\u0305")
        buf.write("\t\6\2\2\u0303\u0306\5\u00d9m\2\u0304\u0306\5\u00d5k\2")
        buf.write("\u0305\u0303\3\2\2\2\u0305\u0304\3\2\2\2\u0306\u00d8\3")
        buf.write("\2\2\2\u0307\u0308\7\62\2\2\u0308\u0309\7Z\2\2\u0309\u030b")
        buf.write("\3\2\2\2\u030a\u030c\5\u00dbn\2\u030b\u030a\3\2\2\2\u030c")
        buf.write("\u030d\3\2\2\2\u030d\u030b\3\2\2\2\u030d\u030e\3\2\2\2")
        buf.write("\u030e\u00da\3\2\2\2\u030f\u0310\t\7\2\2\u0310\u00dc\3")
        buf.write("\2\2\2\u0311\u0312\7]\2\2\u0312\u0313\bo\6\2\u0313\u00de")
        buf.write("\3\2\2\2\u0314\u0315\7_\2\2\u0315\u0316\bp\7\2\u0316\u00e0")
        buf.write("\3\2\2\2\u0317\u0318\7}\2\2\u0318\u0319\bq\b\2\u0319\u00e2")
        buf.write("\3\2\2\2\u031a\u031b\7\177\2\2\u031b\u031c\br\t\2\u031c")
        buf.write("\u00e4\3\2\2\2\u031d\u031e\7*\2\2\u031e\u031f\bs\n\2\u031f")
        buf.write("\u00e6\3\2\2\2\u0320\u0321\7+\2\2\u0321\u0322\bt\13\2")
        buf.write("\u0322\u00e8\3\2\2\2\u0323\u0324\7=\2\2\u0324\u00ea\3")
        buf.write("\2\2\2\u0325\u0328\5\u00edw\2\u0326\u0328\5\u00efx\2\u0327")
        buf.write("\u0325\3\2\2\2\u0327\u0326\3\2\2\2\u0328\u00ec\3\2\2\2")
        buf.write("\u0329\u032e\7)\2\2\u032a\u032d\5\u00f5{\2\u032b\u032d")
        buf.write("\n\b\2\2\u032c\u032a\3\2\2\2\u032c\u032b\3\2\2\2\u032d")
        buf.write("\u0330\3\2\2\2\u032e\u032c\3\2\2\2\u032e\u032f\3\2\2\2")
        buf.write("\u032f\u0331\3\2\2\2\u0330\u032e\3\2\2\2\u0331\u033c\7")
        buf.write(")\2\2\u0332\u0337\7$\2\2\u0333\u0336\5\u00f5{\2\u0334")
        buf.write("\u0336\n\t\2\2\u0335\u0333\3\2\2\2\u0335\u0334\3\2\2\2")
        buf.write("\u0336\u0339\3\2\2\2\u0337\u0335\3\2\2\2\u0337\u0338\3")
        buf.write("\2\2\2\u0338\u033a\3\2\2\2\u0339\u0337\3\2\2\2\u033a\u033c")
        buf.write("\7$\2\2\u033b\u0329\3\2\2\2\u033b\u0332\3\2\2\2\u033c")
        buf.write("\u00ee\3\2\2\2\u033d\u033e\7)\2\2\u033e\u033f\7)\2\2\u033f")
        buf.write("\u0340\7)\2\2\u0340\u0344\3\2\2\2\u0341\u0343\5\u00f1")
        buf.write("y\2\u0342\u0341\3\2\2\2\u0343\u0346\3\2\2\2\u0344\u0345")
        buf.write("\3\2\2\2\u0344\u0342\3\2\2\2\u0345\u0347\3\2\2\2\u0346")
        buf.write("\u0344\3\2\2\2\u0347\u0348\7)\2\2\u0348\u0349\7)\2\2\u0349")
        buf.write("\u0358\7)\2\2\u034a\u034b\7$\2\2\u034b\u034c\7$\2\2\u034c")
        buf.write("\u034d\7$\2\2\u034d\u0351\3\2\2\2\u034e\u0350\5\u00f1")
        buf.write("y\2\u034f\u034e\3\2\2\2\u0350\u0353\3\2\2\2\u0351\u0352")
        buf.write("\3\2\2\2\u0351\u034f\3\2\2\2\u0352\u0354\3\2\2\2\u0353")
        buf.write("\u0351\3\2\2\2\u0354\u0355\7$\2\2\u0355\u0356\7$\2\2\u0356")
        buf.write("\u0358\7$\2\2\u0357\u033d\3\2\2\2\u0357\u034a\3\2\2\2")
        buf.write("\u0358\u00f0\3\2\2\2\u0359\u035c\5\u00f3z\2\u035a\u035c")
        buf.write("\5\u00f5{\2\u035b\u0359\3\2\2\2\u035b\u035a\3\2\2\2\u035c")
        buf.write("\u00f2\3\2\2\2\u035d\u035e\n\n\2\2\u035e\u00f4\3\2\2\2")
        buf.write("\u035f\u0360\7^\2\2\u0360\u0364\13\2\2\2\u0361\u0362\7")
        buf.write("^\2\2\u0362\u0364\5m\67\2\u0363\u035f\3\2\2\2\u0363\u0361")
        buf.write("\3\2\2\2\u0364\u00f6\3\2\2\2\36\2\u01c9\u01cf\u01d5\u01d8")
        buf.write("\u01df\u01e4\u01e9\u01f1\u01fa\u01fd\u02e7\u02f4\u02f9")
        buf.write("\u02ff\u0305\u030d\u0327\u032c\u032e\u0335\u0337\u033b")
        buf.write("\u0344\u0351\u0357\u035b\u0363\f\3\67\2\b\2\2\3c\3\3d")
        buf.write("\4\3o\5\3p\6\3q\7\3r\b\3s\t\3t\n")
        return buf.getvalue()


class HarmonyLexer(Lexer):

    atn = ATNDeserializer().deserialize(serializedATN())

    decisionsToDFA = [ DFA(ds, i) for i, ds in enumerate(atn.decisionToState) ]

    T__0 = 1
    T__1 = 2
    T__2 = 3
    T__3 = 4
    T__4 = 5
    T__5 = 6
    T__6 = 7
    T__7 = 8
    T__8 = 9
    T__9 = 10
    T__10 = 11
    T__11 = 12
    T__12 = 13
    T__13 = 14
    T__14 = 15
    T__15 = 16
    T__16 = 17
    T__17 = 18
    T__18 = 19
    T__19 = 20
    T__20 = 21
    T__21 = 22
    T__22 = 23
    T__23 = 24
    T__24 = 25
    T__25 = 26
    T__26 = 27
    T__27 = 28
    T__28 = 29
    T__29 = 30
    T__30 = 31
    T__31 = 32
    T__32 = 33
    T__33 = 34
    T__34 = 35
    T__35 = 36
    T__36 = 37
    T__37 = 38
    T__38 = 39
    T__39 = 40
    T__40 = 41
    T__41 = 42
    T__42 = 43
    T__43 = 44
    T__44 = 45
    T__45 = 46
    T__46 = 47
    T__47 = 48
    T__48 = 49
    T__49 = 50
    T__50 = 51
    T__51 = 52
    T__52 = 53
    NL = 54
    WS = 55
    COMMENT_START = 56
    OPEN_MULTI_COMMENT = 57
    CLOSE_MULTI_COMMENT = 58
    POINTER_OF = 59
    STAR = 60
    AS = 61
    DOT = 62
    IMPORT = 63
    PRINT = 64
    FROM = 65
    RANGE = 66
    SETINTLEVEL = 67
    ARROW = 68
    SAVE = 69
    STOP = 70
    LAMBDA = 71
    ADDRESS_OF = 72
    NOT = 73
    COMMA = 74
    CONST = 75
    AWAIT = 76
    ASSERT = 77
    VAR = 78
    TRAP = 79
    PASS = 80
    DEL = 81
    SPAWN = 82
    INVARIANT = 83
    GO = 84
    SEQUENTIAL = 85
    WHEN = 86
    LET = 87
    IF = 88
    ELIF = 89
    ELSE = 90
    AT = 91
    WHILE = 92
    DEF = 93
    EXISTS = 94
    WHERE = 95
    EQ = 96
    FOR = 97
    IN = 98
    COLON = 99
    NONE = 100
    ATOMICALLY = 101
    BOOL = 102
    ETERNAL = 103
    INT = 104
    NAME = 105
    ATOM = 106
    HEX_INTEGER = 107
    OPEN_BRACK = 108
    CLOSE_BRACK = 109
    OPEN_BRACES = 110
    CLOSE_BRACES = 111
    OPEN_PAREN = 112
    CLOSE_PAREN = 113
    SEMI_COLON = 114
    STRING = 115

    channelNames = [ u"DEFAULT_TOKEN_CHANNEL", u"HIDDEN" ]

    modeNames = [ "DEFAULT_MODE" ]

    literalNames = [ "<INVALID>",
            "'and'", "'or'", "'=>'", "'&'", "'|'", "'^'", "'-'", "'+'", 
            "'//'", "'/'", "'%'", "'mod'", "'**'", "'<<'", "'>>'", "'=='", 
            "'!='", "'<'", "'<='", "'>'", "'>='", "'~'", "'abs'", "'atLabel'", 
            "'countLabel'", "'get_context'", "'contexts'", "'isEmpty'", 
            "'min'", "'max'", "'len'", "'str'", "'any'", "'all'", "'keys'", 
            "'hash'", "'choose'", "'end'", "'and='", "'or='", "'=>='", "'&='", 
            "'|='", "'^='", "'-='", "'+='", "'*='", "'/='", "'//='", "'%='", 
            "'mod='", "'**='", "'>>='", "'#'", "'(*'", "'*)'", "'!'", "'*'", 
            "'as'", "'.'", "'import'", "'print'", "'from'", "'..'", "'setintlevel'", 
            "'->'", "'save'", "'stop'", "'lambda'", "'?'", "'not'", "','", 
            "'const'", "'await'", "'assert'", "'var'", "'trap'", "'pass'", 
            "'del'", "'spawn'", "'invariant'", "'go'", "'sequential'", "'when'", 
            "'let'", "'if'", "'elif'", "'else'", "'@'", "'while'", "'def'", 
            "'exists'", "'where'", "'='", "'for'", "'in'", "':'", "'None'", 
            "'atomically'", "'eternal'", "'['", "']'", "'{'", "'}'", "'('", 
            "')'", "';'" ]

    symbolicNames = [ "<INVALID>",
            "NL", "WS", "COMMENT_START", "OPEN_MULTI_COMMENT", "CLOSE_MULTI_COMMENT", 
            "POINTER_OF", "STAR", "AS", "DOT", "IMPORT", "PRINT", "FROM", 
            "RANGE", "SETINTLEVEL", "ARROW", "SAVE", "STOP", "LAMBDA", "ADDRESS_OF", 
            "NOT", "COMMA", "CONST", "AWAIT", "ASSERT", "VAR", "TRAP", "PASS", 
            "DEL", "SPAWN", "INVARIANT", "GO", "SEQUENTIAL", "WHEN", "LET", 
            "IF", "ELIF", "ELSE", "AT", "WHILE", "DEF", "EXISTS", "WHERE", 
            "EQ", "FOR", "IN", "COLON", "NONE", "ATOMICALLY", "BOOL", "ETERNAL", 
            "INT", "NAME", "ATOM", "HEX_INTEGER", "OPEN_BRACK", "CLOSE_BRACK", 
            "OPEN_BRACES", "CLOSE_BRACES", "OPEN_PAREN", "CLOSE_PAREN", 
            "SEMI_COLON", "STRING" ]

    ruleNames = [ "T__0", "T__1", "T__2", "T__3", "T__4", "T__5", "T__6", 
                  "T__7", "T__8", "T__9", "T__10", "T__11", "T__12", "T__13", 
                  "T__14", "T__15", "T__16", "T__17", "T__18", "T__19", 
                  "T__20", "T__21", "T__22", "T__23", "T__24", "T__25", 
                  "T__26", "T__27", "T__28", "T__29", "T__30", "T__31", 
                  "T__32", "T__33", "T__34", "T__35", "T__36", "T__37", 
                  "T__38", "T__39", "T__40", "T__41", "T__42", "T__43", 
                  "T__44", "T__45", "T__46", "T__47", "T__48", "T__49", 
                  "T__50", "T__51", "T__52", "NL", "WS", "COMMENT", "COMMENT_START", 
                  "OPEN_MULTI_COMMENT", "CLOSE_MULTI_COMMENT", "POINTER_OF", 
                  "STAR", "AS", "DOT", "IMPORT", "PRINT", "FROM", "RANGE", 
                  "SETINTLEVEL", "ARROW", "SAVE", "STOP", "LAMBDA", "ADDRESS_OF", 
                  "NOT", "COMMA", "CONST", "AWAIT", "ASSERT", "VAR", "TRAP", 
                  "PASS", "DEL", "SPAWN", "INVARIANT", "GO", "SEQUENTIAL", 
                  "WHEN", "LET", "IF", "ELIF", "ELSE", "AT", "WHILE", "DEF", 
                  "EXISTS", "WHERE", "EQ", "FOR", "IN", "COLON", "NONE", 
                  "ATOMICALLY", "BOOL", "ETERNAL", "INT", "NAME", "ATOM", 
                  "HEX_INTEGER", "HEX_DIGIT", "OPEN_BRACK", "CLOSE_BRACK", 
                  "OPEN_BRACES", "CLOSE_BRACES", "OPEN_PAREN", "CLOSE_PAREN", 
                  "SEMI_COLON", "STRING", "SHORT_STRING", "LONG_STRING", 
                  "LONG_STRING_ITEM", "LONG_STRING_CHAR", "STRING_ESCAPE_SEQ" ]

    grammarFileName = "Harmony.g4"

    def __init__(self, input=None, output:TextIO = sys.stdout):
        super().__init__(input, output)
        self.checkVersion("4.9.3")
        self._interp = LexerATNSimulator(self, self.atn, self.decisionsToDFA, PredictionContextCache())
        self._actions = None
        self._predicates = None



    opened_for = 0
    opened = 0

    class HarmonyDenter(ModifiedDenterHelper):
        def __init__(self, lexer, nl_token, colon_token, indent_token, dedent_token, ignore_eof):
            super().__init__(lexer, nl_token, colon_token, indent_token, dedent_token, ignore_eof)
            self.lexer: HarmonyLexer = lexer

        def pull_token(self):
            return super(HarmonyLexer, self.lexer).nextToken()

    denter = None
    def nextToken(self):
        if not self.denter:
            self.denter = self.HarmonyDenter(self, self.NL, self.COLON, HarmonyParser.INDENT, HarmonyParser.DEDENT, ignore_eof=False)
        token = self.denter.next_token()
        return token


    def action(self, localctx:RuleContext, ruleIndex:int, actionIndex:int):
        if self._actions is None:
            actions = dict()
            actions[53] = self.NL_action 
            actions[97] = self.FOR_action 
            actions[98] = self.IN_action 
            actions[109] = self.OPEN_BRACK_action 
            actions[110] = self.CLOSE_BRACK_action 
            actions[111] = self.OPEN_BRACES_action 
            actions[112] = self.CLOSE_BRACES_action 
            actions[113] = self.OPEN_PAREN_action 
            actions[114] = self.CLOSE_PAREN_action 
            self._actions = actions
        action = self._actions.get(ruleIndex, None)
        if action is not None:
            action(localctx, actionIndex)
        else:
            raise Exception("No registered action for:" + str(ruleIndex))


    def NL_action(self, localctx:RuleContext , actionIndex:int):
        if actionIndex == 0:

            if self.opened or self.opened_for:
                self.skip()

     

    def FOR_action(self, localctx:RuleContext , actionIndex:int):
        if actionIndex == 1:
            self.opened_for += 1
     

    def IN_action(self, localctx:RuleContext , actionIndex:int):
        if actionIndex == 2:

            if self.opened_for > 0:
                self.opened_for -= 1

     

    def OPEN_BRACK_action(self, localctx:RuleContext , actionIndex:int):
        if actionIndex == 3:
            self.opened += 1
     

    def CLOSE_BRACK_action(self, localctx:RuleContext , actionIndex:int):
        if actionIndex == 4:
            self.opened -= 1
     

    def OPEN_BRACES_action(self, localctx:RuleContext , actionIndex:int):
        if actionIndex == 5:
            self.opened += 1
     

    def CLOSE_BRACES_action(self, localctx:RuleContext , actionIndex:int):
        if actionIndex == 6:
            self.opened -= 1
     

    def OPEN_PAREN_action(self, localctx:RuleContext , actionIndex:int):
        if actionIndex == 7:
            self.opened += 1
     

    def CLOSE_PAREN_action(self, localctx:RuleContext , actionIndex:int):
        if actionIndex == 8:
            self.opened -= 1
     


