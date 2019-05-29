# @TEST-EXEC: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

type myrecord : record {
	ii: int &optional;
	cc: count &optional;
};

# Allow coercion from count values to int
global globalint: myrecord &redef;
redef globalint = [$ii = 2];

event zeek_init()
	{
	# Allow coercion from count values to int
	local intconvert1 = myrecord($ii = 3);
	local intconvert2: myrecord = record($ii = 4);
	local intconvert3: myrecord = [$ii = 5];

	local intconvert4: myrecord;
	intconvert4$ii = 6;

	# Throw an error for trying to coerce negative values to unsigned
	local negative = myrecord($cc = -5);

	# This value is INT64_MAX+1, which overflows a signed integer and
	# throws an error
	local overflow = myrecord($ii = 9223372036854775808);
	}
