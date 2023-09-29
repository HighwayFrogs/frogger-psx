/******************************************************************************
*%%%% mr_anim3.c
*------------------------------------------------------------------------------
*
*	Functions for handling flipbook environments
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	18.06.97	Tim Closs		Created
*
*%%%**************************************************************************/

#include "mr_all.h"


/******************************************************************************
*%%%% MRAnimEnvFlipbookCreate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ANIM_ENV*	env = 	MRAnimEnvFlipbookCreate(MR_VOID)
*
*	FUNCTION	Allocates space for and initialises a flipbook anim environmenet
*
*	RESULT		env			-	ptr to environment, or NULL if failed
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	18.06.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_ANIM_ENV*	MRAnimEnvFlipbookCreate(MR_VOID)
{
	MR_ANIM_ENV* env;


	env	= MRAllocMem(sizeof(MR_ANIM_ENV) + sizeof(MR_ANIM_ENV_FLIPBOOK), "MRAN_ENV");

	env->ae_prev_node 			= NULL;
	env->ae_next_node 			= NULL;
	env->ae_flags				= (MR_ANIM_ENV_IS_FLIPBOOK | MR_ANIM_ENV_DEFAULT_FLAGS);
	env->ae_special_flags		= NULL;
	env->ae_update_count		= 0;
	env->ae_update_period		= 1;
	env->ae_vp_inst_count		= 0;
	env->ae_header				= NULL;
	env->ae_model_set			= NULL;
	env->ae_extra.ae_extra_void	= ((MR_UBYTE*)env) + sizeof(MR_ANIM_ENV);

	// Set up FLIPBOOK stuff
	env->ae_extra.ae_extra_env_flipbook->ae_events = NULL;

	MRNumber_of_anim_envs++;
	return(env);
}


/******************************************************************************
*%%%% MRAnimEnvFlipbookLoad
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimEnvFlipbookLoad(
*						MR_ANIM_ENV*	env,
*						MR_MOF*			mof)
*
*	FUNCTION	Takes a static MOF and loads it into a flipbook environment
*
*	INPUTS		env		-	ptr to empty environment structure
*				mof		-	ptr to MR_MOF (static flipbook file)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	18.06.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRAnimEnvFlipbookLoad(	MR_ANIM_ENV*	env,
								MR_MOF*			mof)
{
	MR_ASSERT(env);
	MR_ASSERT(mof);
	MR_ASSERT(mof->mm_flags & MR_MOF_FLIPBOOK);

	env->ae_header	= (MR_ANIM_HEADER*)mof;
}


/******************************************************************************
*%%%% MRAnimEnvFlipbookCreateWhole
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ANIM_ENV*	env = 	MRAnimEnvFlipbookCreateWhole(
*										MR_MOF*		mof,
*										MR_USHORT	obj_flags,
*										MR_FRAME*	frame)
*
*	INPUTS		mof			-	ptr to MR_MOF (static flipbook file)
*				obj_flags	-	flags for MR_OBJECT of type MR_MESH
*				frame		-	ptr to frame
*
*	FUNCTION	Allocates space for and initialises a flipbook environment, then
*				loads a model into it, creates a mesh and links the environment
*
*	RESULT		env			-	ptr to environment, or NULL if failed
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	18.06.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_ANIM_ENV*	MRAnimEnvFlipbookCreateWhole(	MR_MOF*		mof,
											 	MR_USHORT	obj_flags,
											 	MR_FRAME*	frame)
{
	MR_ANIM_ENV*	env;
	

	MR_ASSERT(mof);
	MR_ASSERT(mof->mm_flags & MR_MOF_FLIPBOOK);
	MR_ASSERT(frame);

	env = MRAnimEnvFlipbookCreate();
	MRAnimEnvFlipbookLoad(env, mof);
	MRAnimEnvCreateMeshes(env, frame, obj_flags);
	MRAnimLinkEnv(env);

	return(env);
}


/******************************************************************************
*%%%% MRAnimEnvFlipbookSetAction
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimEnvFlipbookSetAction(
*						MR_ANIM_ENV*	env,
*						MR_SHORT		action)
*
*	FUNCTION	Change the action of a model within an environment
*
*	INPUTS		env			-	ptr to animation environment (flipbook)
*				action		-	action number (-1 for no action)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	18.06.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRAnimEnvFlipbookSetAction(	MR_ANIM_ENV*	env,
									MR_SHORT		action)
{
	MR_ANIM_ENV_FLIPBOOK*	env_flip;
	MR_PART_FLIPBOOK*		flipbook;

	
	MR_ASSERT(env);

	env_flip = env->ae_extra.ae_extra_env_flipbook;
	
	if (action == -1)
		{
		// Turn model off
		env_flip->ae_action_number	= -1;
		env_flip->ae_total_cels		= -1;
		env_flip->ae_cel_number		= -1;
		}
	else
		{
		MR_ASSERTMSG(action < ((MR_PART_FLIPBOOK*)((MR_PART*)(((MR_MOF*)env->ae_header) + 1))->mp_pad1)->mp_numactions, "Action number too big");
		env_flip->ae_action_number	= action;
		flipbook					= (MR_PART_FLIPBOOK*)((MR_PART*)(((MR_MOF*)env->ae_header) + 1))->mp_pad1;
		env_flip->ae_total_cels		= (((MR_PART_FLIPBOOK_ACTION*)(flipbook + 1)) + action)->mp_numpartcels;
		env_flip->ae_cel_number 	= -1;
		}
}


/******************************************************************************
*%%%% MRAnimEnvFlipbookSetCel
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimEnvFlipbookSetCel(
*						MR_ANIM_ENV*	env,
*						MR_SHORT		cel)
*
*	FUNCTION	Change the cel of a model within an environment
*
*	INPUTS		env			-	ptr to animation environment (flipbook)
*				cel			-	cel number (-1 for no cel)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	18.06.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRAnimEnvFlipbookSetCel(MR_ANIM_ENV*	env,
								MR_SHORT		cel)
{
	MR_ANIM_ENV_FLIPBOOK*	env_flip;
	MR_PART_FLIPBOOK*		flipbook;
	

	MR_ASSERT(env);

	env_flip = env->ae_extra.ae_extra_env_flipbook;
	
	if (cel == -1)
		{
		// Turn model off
		env_flip->ae_cel_number = -1;
		}
	else
		{
		flipbook = (MR_PART_FLIPBOOK*)((MR_PART*)(((MR_MOF*)env->ae_header) + 1))->mp_pad1;
		MR_ASSERTMSG(cel < (((MR_PART_FLIPBOOK_ACTION*)(flipbook + 1)) + env_flip->ae_action_number)->mp_numpartcels, "Cel number too big");

		env_flip->ae_cel_number = cel;
		}
}
