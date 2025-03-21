# GTE macros

.macro rtps
		.word	0x4A180001
.endm

.macro rtpt
		.word	0x4A280030
.endm

.macro dpcl
		.word	0x4A680029
.endm

.macro dpcs
		.word	0x4A780010
.endm

.macro dpct
		.word	0x4AF8002A
.endm

.macro intpl
		.word	0x4A980011
.endm

.macro ncs
		.word	0x4AC8041E
.endm

.macro nct
		.word	0x4AD80420
.endm

.macro ncds
		.word	0x4AE80413
.endm

.macro ncdt
		.word	0x4AF80416
.endm

.macro nccs
		.word	0x4B08041B
.endm

.macro ncct
		.word	0x4B18043F
.endm

.macro cdp
		.word	0x4B280414
.endm

.macro cc
		.word	0x4B38041C
.endm

.macro nclip
		.word	0x4B400006
.endm

.macro avsz3
		.word	0x4B58002D
.endm

.macro avsz4
		.word	0x4B68002E
.endm

.macro mvmva sf, mx, v, cv, lm
		.word	0x4A400012|\sf<<19|\mx<<17|\v<<15|\cv<<13|\lm<<10
.endm

.macro sqr sf
		.word	0x4AA00428|\sf<<19
.endm

.macro op sf
		.word	0x4B70000C|\sf<<19
.endm

.macro gpf sf
		.word	0x4B90003D|\sf<<19
.endm

.macro gpl sf
		.word	0x4BA0003E|\sf<<19
.endm
