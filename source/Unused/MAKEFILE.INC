        symmunge /i main.sym 

	resetps 1
#//	run $(PS_RESET_DELAY) $(PS_KERNEL_PATCH)
#//	delay 50
	run $(PS_RESET_DELAY) $(PS_RUN_OPTION) main.cpe

