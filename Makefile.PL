# $Id: Makefile.PL,v 1.4 2002/10/29 15:09:05 reggers Exp $

use ExtUtils::MakeMaker;

WriteMakefile(
	NAME          => 'Apache::AuthenFile',
	DISTNAME      => 'Apache-AuthenFile',
	VERSION_FROM  => 'AuthenFile.pm',

	PREREQ_PM	=> {
		IO::File => 0
	},

	dist	=> {
		COMPRESS=>"gzip",
		SUFFIX=>"gz"
	}
);
