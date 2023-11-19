/******************************************************************************
*%%%% camera.c
*------------------------------------------------------------------------------
*
*	Camera handling
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	15.04.97	Tim Closs		Created
*	08.07.97	Tim Closs		Added ca_offset_origin to CAMERA for Gary
*	30.07.97	Martin Kift		Added momentum code to camera in x/z plane
*
*%%%**************************************************************************/

#include "camera.h"
#include "frog.h"
#include "gamesys.h"
#include "misc.h"

CAMERA	Cameras[SYSTEM_MAX_VIEWPORTS];
#ifdef CAMERA_DEBUG_REMOTE
MR_MAT	Camera_debug_remote_matrix;
#endif


/******************************************************************************
*%%%% InitialiseCameras
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	InitialiseCameras(MR_VOID)
*
*	FUNCTION	Initialise cameras for all viewports
*	MATCH		https://decomp.me/scratch/nlPNM	(By Kneesnap)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.05.97	Tim Closs		Created
*	30.10.23	Kneesnap		Added ORG multiplayer check to byte-match PSX Build 71.
*
*%%%**************************************************************************/

MR_VOID	InitialiseCameras(MR_VOID)
{
	MR_ULONG	i;
	
	// Change the camera offset in multiplayer ORG levels.
	if ((Game_total_players > 2) && (Game_map_theme == THEME_ORG))
		{
		Map_general_header->gh_default_camera_source_ofs.vy = (Map_general_header->gh_default_camera_source_ofs.vy * 3 >> 2);
		Map_general_header->gh_default_camera_target_ofs.vy = (Map_general_header->gh_default_camera_target_ofs.vy * 3 >> 2);
		}

#ifdef CAMERA_FORCE_DEFAULT
	MR_SET_SVEC(&Map_general_header->gh_default_camera_source_ofs, CAMERA_FROG_DEFAULT_SOURCE_OFS_X, CAMERA_FROG_DEFAULT_SOURCE_OFS_Y, CAMERA_FROG_DEFAULT_SOURCE_OFS_Z);
	MR_SET_SVEC(&Map_general_header->gh_default_camera_target_ofs, CAMERA_FROG_DEFAULT_TARGET_OFS_X, CAMERA_FROG_DEFAULT_TARGET_OFS_Y, CAMERA_FROG_DEFAULT_TARGET_OFS_Z);
#endif

	for (i = 0; i < Game_total_viewports; i++)
		{
		InitialiseCamera(&Cameras[i], Game_viewports[i]);
#ifdef PSX
		Cameras[i].ca_id = i;
#else
		if (MNIsNetGameRunning())
			Cameras[i].ca_id = Frog_local_id;
		else
			Cameras[i].ca_id = i;
#endif
		ResetCamera(&Cameras[i]);
		}

	// Reinit the api matrices, since they seem to have be trampled by some
	// of the options screens $mk
	MR_INIT_MAT(&MRRot_matrix_X);
	MR_INIT_MAT(&MRRot_matrix_Y);
	MR_INIT_MAT(&MRRot_matrix_Z);
}


/******************************************************************************
*%%%% InitialiseCamera
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	InitialiseCamera(
*						CAMERA*		camera,
*						MR_VIEWPORT	vp)
*
*	FUNCTION	Initialise a camera in a viewport
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	InitialiseCamera(	CAMERA*			camera,
							MR_VIEWPORT*	vp)
{
#ifdef	CAMERA_DEBUG_REMOTE
	MR_INIT_MAT(&Camera_debug_remote_matrix);
	camera->ca_matrix = &Camera_debug_remote_matrix;
#else
	camera->ca_matrix = &vp->vp_camera->fr_matrix;
#endif
}


/******************************************************************************
*%%%% ResetCameras
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ResetCameras(MR_VOID)
*
*	FUNCTION	Reset all cameras
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	ResetCameras(MR_VOID)
{
	MR_ULONG	i;
	

	for (i = 0; i < Game_total_viewports; i++)
		ResetCamera(&Cameras[i]);
}	


/******************************************************************************
*%%%% ResetCamera
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ResetCamera(
*						CAMERA*	camera)
*
*	FUNCTION	Reset a camera
*
*	INPUTS		camera	-	camera to reset
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	22.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	ResetCamera(CAMERA*	camera)
{
	MR_SET_SVEC(&camera->ca_current_source_ofs, CAMERA_FROG_START_SOURCE_OFS_X, CAMERA_FROG_START_SOURCE_OFS_Y, CAMERA_FROG_START_SOURCE_OFS_Z);
	MR_SET_SVEC(&camera->ca_current_target_ofs, CAMERA_FROG_START_TARGET_OFS_X, CAMERA_FROG_START_TARGET_OFS_Y, CAMERA_FROG_START_TARGET_OFS_Z);
	CAMERA_SET_DEFAULT_NEXT_SOURCE_OFS;
	CAMERA_SET_DEFAULT_NEXT_TARGET_OFS;

	camera->ca_zone		 				= NULL;
	camera->ca_move_timer				= CAMERA_START_SWINGOUT_TIME;
	camera->ca_twist_counter			= 0;
	MR_CLEAR_VEC(&camera->ca_current);

	camera->ca_flags					= NULL;
	camera->ca_mode						= CAMERA_MODE_START;
	camera->ca_mod_matrix_delta_ytheta	= 0;
	camera->ca_offset_origin			= (MR_VEC*)Frogs[camera->ca_id].fr_lwtrans->t;

	MR_INIT_MAT(&camera->ca_mod_matrix);

	MR_SET_VEC(&camera->ca_direction_vectors[FROG_DIRECTION_N],  0, 		0,  0x1000);
	MR_SET_VEC(&camera->ca_direction_vectors[FROG_DIRECTION_E],  0x1000, 	0,       0);
	MR_SET_VEC(&camera->ca_direction_vectors[FROG_DIRECTION_S],  0, 		0, -0x1000);
	MR_SET_VEC(&camera->ca_direction_vectors[FROG_DIRECTION_W], -0x1000, 	0,       0);
}


/******************************************************************************
*%%%% UpdateCameras
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	UpdateCameras(MR_VOID)
*
*	FUNCTION	Update all cameras
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	UpdateCameras(MR_VOID)
{
	MR_ULONG	i;
	

	for (i = 0; i < Game_total_viewports; i++)
		{
		UpdateCamera(&Cameras[i]);
		}
}	


/******************************************************************************
*%%%% UpdateCamera
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	UpdateCamera(
*						CAMERA*	camera)
*
*	FUNCTION	Update camera position and rotation
*
*	INPUTS		camera	-	camera to update
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.05.97	Tim Closs		Created
*	07.06.97	Martin Kift		Added CAMERA_IGNORE_FROG_Y flag
*	19.08.97	Tim Closs		Recoded the way it works out the control quadrant
*	16.11.23	Kneesnap		Byte-match PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID	UpdateCamera(CAMERA*	camera)
{
	MR_VEC			vec, target;
	MR_SVEC			svec;
	MR_LONG			dest_x, dest_y, dest_z;
	FROG*			frog;
	MR_LONG			d, i, cos, sin;
	MR_VEC			source_ofs;
	MR_VEC			target_ofs;
	MR_MAT			matrix;
	MR_MAT*			matrix_ptr;
	MR_BOOL			twist;
	MR_BOOL			twist_end;
	MR_MAT*			cam_matrix;
	MR_VIEWPORT*	vp;
	MR_MAT*			camera_mod_matrix;
	MR_MAT			mod_matrix;

#ifdef CAMERA_DEBUG_DISPLAY_GRID
	MR_LONG			grid_x, grid_z;
#endif

	frog 		= &Frogs[camera->ca_id];
	cam_matrix	= camera->ca_matrix;
	vp			= Game_viewports[camera->ca_id];

#ifdef	CAMERA_DEBUG_REMOTE
	// Translation
	if (MR_CHECK_PAD_HELD(MR_INPUT_PORT_0, FR_LEFT))
		vp->vp_camera->fr_matrix.t[0] -= 0x40;
	if (MR_CHECK_PAD_HELD(MR_INPUT_PORT_0, FR_RIGHT))
		vp->vp_camera->fr_matrix.t[0] += 0x40;
	if (MR_CHECK_PAD_HELD(MR_INPUT_PORT_0, FR_UP))
		vp->vp_camera->fr_matrix.t[2] += 0x40;
	if (MR_CHECK_PAD_HELD(MR_INPUT_PORT_0, FR_DOWN))
		vp->vp_camera->fr_matrix.t[2] -= 0x40;
	if (MR_CHECK_PAD_HELD(MR_INPUT_PORT_0, FRR_GREEN))
		vp->vp_camera->fr_matrix.t[1] += 0x40;
	if (MR_CHECK_PAD_HELD(MR_INPUT_PORT_0, FRR_BLUE))
		vp->vp_camera->fr_matrix.t[1] -= 0x40;

	MR_SET_VEC(&vp->vp_camera->fr_rotation, -0x3a0 << 16, 0, 0);
	vp->vp_camera->fr_flags |= MR_FRAME_REBUILD;

#ifdef CAMERA_DEBUG_DISPLAY_GRID
	grid_x = (cam_matrix->t[0] - Grid_base_x) >> 8;
	grid_z = (cam_matrix->t[2] - Grid_base_z) >> 8;
	MapDebugDisplayGrid(grid_x - 5, grid_z - 5, grid_x + 5, grid_z + 5, frog->fr_lwtrans->t[1]);
#endif
#endif

	switch(camera->ca_mode)
		{
		//---------------------------------------------------------------------
		case CAMERA_MODE_START:
			if (Game_start_timer <= camera->ca_move_timer)
				{
				// Have held close-up for long enough: now set destination according to current frog zone
				camera->ca_mode	= CAMERA_MODE_FIXED_SWEEP;
				if (frog->fr_cam_zone)
					{
					camera->ca_zone = frog->fr_cam_zone;
					MR_COPY_SVEC(&camera->ca_next_source_ofs, (MR_SVEC*)&((ZONE_CAMERA*)(camera->ca_zone + 1))->zc_source_ofs_n);
					MR_COPY_SVEC(&camera->ca_next_target_ofs, (MR_SVEC*)&((ZONE_CAMERA*)(camera->ca_zone + 1))->zc_target_ofs_n);
					}
				else
					{
					CAMERA_SET_DEFAULT_NEXT_SOURCE_OFS;
					CAMERA_SET_DEFAULT_NEXT_TARGET_OFS;
					}
				}
	
			// camera->ca offset from frog
			cam_matrix->t[0] = camera->ca_offset_origin->vx	+ camera->ca_current_source_ofs.vx;
			cam_matrix->t[1] = camera->ca_offset_origin->vy	+ camera->ca_current_source_ofs.vy;
			cam_matrix->t[2] = camera->ca_offset_origin->vz	+ camera->ca_current_source_ofs.vz;
	
			// camera->ca look-at offset from frog
			target.vx = camera->ca_offset_origin->vx + camera->ca_current_target_ofs.vx;
			target.vy = camera->ca_offset_origin->vy + camera->ca_current_target_ofs.vy;
			target.vz = camera->ca_offset_origin->vz + camera->ca_current_target_ofs.vz;
	
			CreateCameraMatrix(camera, &target);
			break;
		//---------------------------------------------------------------------
		case CAMERA_MODE_FIXED_SWEEP:
			// Fixed sweep with no camera modification matrix
			//
			// Evaluate current offsets
			if (!(--camera->ca_move_timer))
				{
				// End of fixed sweep
				camera->ca_mode = CAMERA_MODE_FOLLOW_FROG;
				MR_COPY_VEC(&camera->ca_current, camera->ca_offset_origin);
				}
			else
				{
				d = (camera->ca_next_source_ofs.vx - camera->ca_current_source_ofs.vx) / camera->ca_move_timer;
				camera->ca_current_source_ofs.vx += d;
				d = (camera->ca_next_source_ofs.vy - camera->ca_current_source_ofs.vy) / camera->ca_move_timer;
				camera->ca_current_source_ofs.vy += d;
				d = (camera->ca_next_source_ofs.vz - camera->ca_current_source_ofs.vz) / camera->ca_move_timer;
				camera->ca_current_source_ofs.vz += d;

				d = (camera->ca_next_target_ofs.vx - camera->ca_current_target_ofs.vx) / camera->ca_move_timer;
				camera->ca_current_target_ofs.vx += d;
				d = (camera->ca_next_target_ofs.vy - camera->ca_current_target_ofs.vy) / camera->ca_move_timer;
				camera->ca_current_target_ofs.vy += d;
				d = (camera->ca_next_target_ofs.vz - camera->ca_current_target_ofs.vz) / camera->ca_move_timer;
				camera->ca_current_target_ofs.vz += d;
				}

			// camera->ca offset from frog
			cam_matrix->t[0] = camera->ca_offset_origin->vx	+ camera->ca_current_source_ofs.vx;
			cam_matrix->t[1] = camera->ca_offset_origin->vy	+ camera->ca_current_source_ofs.vy;
			cam_matrix->t[2] = camera->ca_offset_origin->vz	+ camera->ca_current_source_ofs.vz;
	
			// camera->ca look-at offset from frog
			target.vx = camera->ca_offset_origin->vx + camera->ca_current_target_ofs.vx;
			target.vy = camera->ca_offset_origin->vy + camera->ca_current_target_ofs.vy;
			target.vz = camera->ca_offset_origin->vz + camera->ca_current_target_ofs.vz;
	
			CreateCameraMatrix(camera, &target);
			break;
		//---------------------------------------------------------------------
		case CAMERA_MODE_FOLLOW_FROG:
#ifndef CAMERA_NO_NEW_ZONES

			// Work out camera matrices (mod_matrix) which is dependent on whether the frog
			// is sitting on an entity. $mk
			if (frog->fr_entity)
				{
				// camera->ca_mod_matrix is multiplied by the (projected) entity transform
				ProjectMatrixOntoWorldXZ(frog->fr_entity->en_live_entity->le_lwtrans, &MRTemp_matrix);
				MRMulMatrixABC(&camera->ca_mod_matrix, &MRTemp_matrix, &mod_matrix);
				camera_mod_matrix = &mod_matrix;
				}
			else
				camera_mod_matrix = &camera->ca_mod_matrix;

			// Update offsets from frog (if moving zones)
			if (frog->fr_cam_zone != camera->ca_zone)
				{
				// Frog has moved out of current camera zone
				camera->ca_move_timer 	= CAMERA_ZONE_MOVE_TIME;

				// Are we in a new camera zone, or no camera zone?
				if (frog->fr_cam_zone)
					{
					// New zone
					if	(
						(camera->ca_zone) &&
						(((ZONE_CAMERA*)(camera->ca_zone + 1))->zc_flags & ZONE_FLAG_ABSOLUTE_Y)
						)
						{
						// Old zone was fixed y zone
						camera->ca_current.vy = 0;//camera->ca_offset_origin->vy;
						}
					camera->ca_zone	= frog->fr_cam_zone;
					if	(
						(camera->ca_zone) &&
						(((ZONE_CAMERA*)(camera->ca_zone + 1))->zc_flags & ZONE_FLAG_ABSOLUTE_Y)
						)
						{
						// New zone is fixed y zone - ca_current.vy becomes camera world Y
						camera->ca_current.vy = camera->ca_matrix->t[1];
						}
	
					i = GetWorldYQuadrantFromMatrix(camera_mod_matrix);

					// If ZONE_CAMERA specifies a direction, force rotation to that specified
					if (((ZONE_CAMERA*)(camera->ca_zone + 1))->zc_direction >= 0)
						{
						d = ((ZONE_CAMERA*)(camera->ca_zone + 1))->zc_direction;
						if (d == ((i + 1) & 3))
							{
							// Force rotation clockwise by 90
							camera->ca_twist_counter 	= 1;
							camera->ca_twist_quadrants	= 1;
							}
						else
						if (d == ((i - 1) & 3))
							{
							// Force rotation anticlockwise by 90
							camera->ca_twist_counter 	= -1;
							camera->ca_twist_quadrants	= 1;
							}
						else
						if (d == ((i + 2) & 3))
							{
							// Force rotation clockwise by 180
							camera->ca_twist_counter 	= 1;
							camera->ca_twist_quadrants	= 2;
							}
						else
							{
							// No rotation required
							}
						i = d;							
						}
					else
						{					
						// Quadrant of ca_mod_matrix about world Y determines which offsets to use
						i = GetWorldYQuadrantFromMatrix(camera_mod_matrix);
						}
					MR_COPY_SVEC(&camera->ca_next_source_ofs, (MR_SVEC*)&((ZONE_CAMERA*)(camera->ca_zone + 1))->zc_source_ofs_n + (i << 1));
					MR_COPY_SVEC(&camera->ca_next_target_ofs, (MR_SVEC*)&((ZONE_CAMERA*)(camera->ca_zone + 1))->zc_target_ofs_n + (i << 1));
					}
				else
					{
					// No zone
					if	(
						(camera->ca_zone) &&
						(((ZONE_CAMERA*)(camera->ca_zone + 1))->zc_flags & ZONE_FLAG_ABSOLUTE_Y)
						)
						{
						// Old zone was fixed y zone
						camera->ca_current.vy = camera->ca_offset_origin->vy;
						CAMERA_SET_DEFAULT_CURRENT_SOURCE_OFS;
						CAMERA_SET_DEFAULT_CURRENT_TARGET_OFS;
						}
					camera->ca_zone	= frog->fr_cam_zone;
					CAMERA_SET_DEFAULT_NEXT_SOURCE_OFS;
					CAMERA_SET_DEFAULT_NEXT_TARGET_OFS;
					}
				}
#endif
			// Evaluate current offsets
			if (camera->ca_move_timer)
				{
				d = (camera->ca_next_source_ofs.vx - camera->ca_current_source_ofs.vx) / camera->ca_move_timer;
				camera->ca_current_source_ofs.vx += d;
				d = (camera->ca_next_source_ofs.vy - camera->ca_current_source_ofs.vy) / camera->ca_move_timer;
				camera->ca_current_source_ofs.vy += d;
				d = (camera->ca_next_source_ofs.vz - camera->ca_current_source_ofs.vz) / camera->ca_move_timer;
				camera->ca_current_source_ofs.vz += d;

				d = (camera->ca_next_target_ofs.vx - camera->ca_current_target_ofs.vx) / camera->ca_move_timer;
				camera->ca_current_target_ofs.vx += d;
				d = (camera->ca_next_target_ofs.vy - camera->ca_current_target_ofs.vy) / camera->ca_move_timer;
				camera->ca_current_target_ofs.vy += d;
				d = (camera->ca_next_target_ofs.vz - camera->ca_current_target_ofs.vz) / camera->ca_move_timer;
				camera->ca_current_target_ofs.vz += d;
				camera->ca_move_timer--;
				}

			// Calculate desired y of camera (before offset)
			if (frog->fr_flags & FROG_FREEFALL)
				{
				dest_y = camera->ca_offset_origin->vy;
				}
			else
			if (frog->fr_mode == FROG_MODE_JUMPING)
				{
				if (frog->fr_flags & FROG_SUPERJUMP)
					dest_y = frog->fr_old_y + (((FROG_SUPERJUMP_TIME - frog->fr_count) * (frog->fr_y - frog->fr_old_y)) / FROG_SUPERJUMP_TIME);
				else
					dest_y = frog->fr_old_y + (((FROG_JUMP_TIME - frog->fr_count) * (frog->fr_y - frog->fr_old_y)) / FROG_JUMP_TIME);
				}
			else
				{
				dest_y = camera->ca_offset_origin->vy;
				}
			// Camera can only plummet so far
			dest_y = MIN(dest_y, 0);
			dest_x = camera->ca_offset_origin->vx;
			dest_z = camera->ca_offset_origin->vz;

			// Sort out twist
			twist		= FALSE;
			twist_end 	= FALSE;
			if (camera->ca_twist_counter > 0)
				{
				twist	= TRUE;
				i		= (camera->ca_twist_counter * 0x400) / CAMERA_TWIST_TIME;
				cos 	= rcos(i);
				sin 	= rsin(i);
				MRRot_matrix_Y.m[0][0] =  cos;
				MRRot_matrix_Y.m[0][2] =  sin;
				MRRot_matrix_Y.m[2][0] = -sin;
				MRRot_matrix_Y.m[2][2] =  cos;

				if (++camera->ca_twist_counter > (CAMERA_TWIST_TIME * camera->ca_twist_quadrants))
					{
					camera->ca_twist_counter 	= 0;
					twist_end					= TRUE;
					frog->fr_entity_angle 		= (frog->fr_entity_angle + camera->ca_twist_quadrants) & 3;
					}
				}
			else
			if (camera->ca_twist_counter < 0)
				{
				twist	= TRUE;
				i		= (camera->ca_twist_counter * 0x400) / CAMERA_TWIST_TIME;
				cos 	= rcos(i);
				sin 	= rsin(i);
				MRRot_matrix_Y.m[0][0] =  cos;
				MRRot_matrix_Y.m[0][2] =  sin;
				MRRot_matrix_Y.m[2][0] = -sin;
				MRRot_matrix_Y.m[2][2] =  cos;

				if (--camera->ca_twist_counter < -(CAMERA_TWIST_TIME * camera->ca_twist_quadrants))
					{
					camera->ca_twist_counter 	= 0;
					twist_end					= TRUE;
					frog->fr_entity_angle 		= (frog->fr_entity_angle - camera->ca_twist_quadrants) & 3;
					}
				}					

			// Sort out correct camera modification
			//
			// First, is ca_mod_matrix being generated from ytheta?
			if (camera->ca_mod_matrix_delta_ytheta)
				{
				camera->ca_mod_matrix_current_ytheta += camera->ca_mod_matrix_delta_ytheta;
				if (camera->ca_mod_matrix_delta_ytheta > 0)
					{
					if (camera->ca_mod_matrix_current_ytheta >= camera->ca_mod_matrix_dest_ytheta)
						{
						camera->ca_mod_matrix_current_ytheta 	= camera->ca_mod_matrix_dest_ytheta;
						camera->ca_mod_matrix_delta_ytheta 		= 0;
						}
					}
				else
					{
					if (camera->ca_mod_matrix_current_ytheta <= camera->ca_mod_matrix_dest_ytheta)
						{
						camera->ca_mod_matrix_current_ytheta 	= camera->ca_mod_matrix_dest_ytheta;
						camera->ca_mod_matrix_delta_ytheta 		= 0;
						}
					}
				// Generate ca_mod_matrix
				cos	= rcos(camera->ca_mod_matrix_current_ytheta);
				sin	= rsin(camera->ca_mod_matrix_current_ytheta);
				camera->ca_mod_matrix.m[0][0] = cos;
				camera->ca_mod_matrix.m[0][1] = 0;
				camera->ca_mod_matrix.m[0][2] = sin;
				camera->ca_mod_matrix.m[1][0] = 0;
				camera->ca_mod_matrix.m[1][1] = 0x1000;
				camera->ca_mod_matrix.m[1][2] = 0;
				camera->ca_mod_matrix.m[2][0] = -sin;
				camera->ca_mod_matrix.m[2][1] = 0;
				camera->ca_mod_matrix.m[2][2] = cos;
				}

			// Include possible twist and entity transforms
			matrix_ptr = &camera->ca_mod_matrix;

			if (twist_end == TRUE)
				MRMulMatrixABB(&MRRot_matrix_Y, matrix_ptr);
			else
			if (twist == TRUE)
				{
				MRMulMatrixABC(&MRRot_matrix_Y, matrix_ptr, &matrix);
				matrix_ptr = &matrix;
				}

			if (frog->fr_entity)
				{
				// camera->ca_mod_matrix is multiplied by the (projected) entity transform
				ProjectMatrixOntoWorldXZ(frog->fr_entity->en_live_entity->le_lwtrans, &MRTemp_matrix);
				MRMulMatrixABC(matrix_ptr, &MRTemp_matrix, &matrix);
				matrix_ptr = &matrix;
				}

			gte_SetRotMatrix(matrix_ptr);
			MRApplyRotMatrix(&camera->ca_current_source_ofs, &source_ofs);
			MRApplyRotMatrix(&camera->ca_current_target_ofs, &target_ofs);

			if	(
				(camera->ca_zone) &&
				(((ZONE_CAMERA*)(camera->ca_zone + 1))->zc_flags & ZONE_FLAG_ABSOLUTE_Y)
				)
				{
				// Fixed y zone - override dest_y
				dest_y = camera->ca_next_source_ofs.vy;
				}
			// Move camera_current.vy towards dest_y
			if (!(camera->ca_flags & CAMERA_IGNORE_FROG_Y))
				{
				if (camera->ca_current.vy < dest_y)
					{
					if ((dest_y - camera->ca_current.vy) < CAMERA_Y_MOVE_RATE)
						camera->ca_current.vy = dest_y;
					else
						camera->ca_current.vy += CAMERA_Y_MOVE_RATE;
					}
				else
				if (camera->ca_current.vy > dest_y)
					{
					if ((camera->ca_current.vy - dest_y) < CAMERA_Y_MOVE_RATE)
						camera->ca_current.vy = dest_y;
					else
						camera->ca_current.vy -= CAMERA_Y_MOVE_RATE;
					}
				}

			// Move camera_current.vx towards dest_x
			if (camera->ca_current.vx < dest_x)
				{
				if ((dest_x - camera->ca_current.vx) < CAMERA_XZ_MINIMUM_OFFSET)
					camera->ca_current.vx = dest_x;
				else
					camera->ca_current.vx += (dest_x - camera->ca_current.vx)>>1;
				}
			else
			if (camera->ca_current.vx > dest_x)
				{
				if ((camera->ca_current.vx - dest_x) < CAMERA_XZ_MINIMUM_OFFSET)
					camera->ca_current.vx = dest_x;
				else
					camera->ca_current.vx -= (camera->ca_current.vx - dest_x)>>1;
				}
			
			// Move camera_current.vz towards dest_z
			if (camera->ca_current.vz < dest_z)
				{
				if ((dest_z - camera->ca_current.vz) < CAMERA_XZ_MINIMUM_OFFSET)
					camera->ca_current.vz = dest_z;
				else
					camera->ca_current.vz += (dest_z - camera->ca_current.vz)>>1;
				}
			else
			if (camera->ca_current.vz > dest_z)
				{
				if ((camera->ca_current.vz - dest_z) < CAMERA_XZ_MINIMUM_OFFSET)
					camera->ca_current.vz = dest_z;
				else
					camera->ca_current.vz -= (camera->ca_current.vz - dest_z)>>1;
				}

			if	(
				(camera->ca_zone) &&
				(((ZONE_CAMERA*)(camera->ca_zone + 1))->zc_flags & ZONE_FLAG_ABSOLUTE_Y)
				)
				{
				// Desired world camera source y is that specified in ZONE_CAMERA (so in ca_current_source_ofs)
				// Desired world camera target y is that specified in ZONE_CAMERA (so in ca_current_target_ofs)
				cam_matrix->t[0] 	= camera->ca_current.vx + source_ofs.vx;
				cam_matrix->t[1] 	= camera->ca_current.vy;
				cam_matrix->t[2] 	= camera->ca_current.vz + source_ofs.vz;
				target.vx			= camera->ca_current.vx + target_ofs.vx;
				target.vy		 	= camera->ca_current_target_ofs.vy;
				target.vz		 	= camera->ca_current.vz + target_ofs.vz;
				}
			else
				{
				MR_ADD_VEC_ABC(&camera->ca_current, &source_ofs, (MR_VEC*)cam_matrix->t);
				MR_ADD_VEC_ABC(&camera->ca_current, &target_ofs, &target);
				}

			CreateCameraMatrix(camera, &target);

			// Set up camera->ca_direction_vectors
			//
			// camera->ca +ve Y axis, projected onto XZ plane, becomes South
			vec.vx = cam_matrix->m[0][1];
			vec.vy = 0;
			vec.vz = cam_matrix->m[2][1];
			MRNormaliseVEC(&vec, &vec);
			MR_COPY_VEC(&camera->ca_direction_vectors[FROG_DIRECTION_S], &vec);
			MR_SUB_VEC_ABC(&Null_vector, &camera->ca_direction_vectors[FROG_DIRECTION_S], &camera->ca_direction_vectors[FROG_DIRECTION_N]);

			// camera->ca +ve X axis, projected onto XZ plane, becomes East
			vec.vx = cam_matrix->m[0][0];
			vec.vy = 0;
			vec.vz = cam_matrix->m[2][0];
			MRNormaliseVEC(&vec, &vec);
			MR_COPY_VEC(&camera->ca_direction_vectors[FROG_DIRECTION_E], &vec);
			MR_SUB_VEC_ABC(&Null_vector, &camera->ca_direction_vectors[FROG_DIRECTION_E], &camera->ca_direction_vectors[FROG_DIRECTION_W]);

			// Set up Frog_controller_directions and Frog_direction_vectors
			if (abs(camera->ca_direction_vectors[FROG_DIRECTION_N].vz) > abs(camera->ca_direction_vectors[FROG_DIRECTION_N].vx))
				{
				if (camera->ca_direction_vectors[FROG_DIRECTION_N].vz > 0)
					{
					// UP is N
					d = FROG_DIRECTION_N;
					}
				else
					{
					// UP is S
					d = FROG_DIRECTION_S;
					}
				}
			else
				{
				if (camera->ca_direction_vectors[FROG_DIRECTION_N].vx > 0)
					{
					// UP is E
					d = FROG_DIRECTION_E;
					}
				else
					{
					// UP is W
					d = FROG_DIRECTION_W;
					}
				}

			for (i = FROG_DIRECTION_N; i <= FROG_DIRECTION_W; i++)
				{
				camera->ca_frog_controller_directions[i] = d;
				MR_COPY_VEC(&camera->ca_frog_direction_vectors[i], &Frog_fixed_vectors[d]);

				d = (d + 1) & 3;
				}

#ifdef DEBUG_DISPLAY_FROG_CAMERA_ZONES
			if (frog->fr_cam_zone_region)
				MapDebugDisplayZoneRegion(frog->fr_cam_zone_region);
#endif
			break;
		//---------------------------------------------------------------------
		}

	// Handle camera shake
	if (camera->ca_flags & CAMERA_FLAG_SHAKING)
		{
		d		= rsin(((camera->ca_shake_duration - camera->ca_shake_timer) * camera->ca_shake_freq_x) / camera->ca_shake_duration);
		svec.vx = (((d * camera->ca_shake_amp_x * camera->ca_shake_timer) >> 0) / camera->ca_shake_duration) >> 16;
		d		= rsin(((camera->ca_shake_duration - camera->ca_shake_timer) * camera->ca_shake_freq_y) / camera->ca_shake_duration);
		svec.vy = (((d * camera->ca_shake_amp_y * camera->ca_shake_timer) >> 0) / camera->ca_shake_duration) >> 16;
		svec.vz = 0;
		MRApplyMatrix(cam_matrix, &svec, &vec);
		MR_ADD_VEC((MR_VEC*)cam_matrix->t, &vec);

		if (!(--camera->ca_shake_timer))
			camera->ca_flags &= ~CAMERA_FLAG_SHAKING;
		}
}


/******************************************************************************
*%%%% ShakeCamera
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ShakeCamera(
*						CAMERA*		camera,
*						MR_LONG		amp,
*						MR_LONG		duration,
*						MR_LONG		freq)
*
*	FUNCTION	Sets up a shake on the specified camera
*
*	INPUTS		camera		-	ptr to camera to shake
*				amp			-	amplitude in world coords
*				duration	-	in game cycles
*				freq		-	frequency of shake
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	23.06.97	Tim Closs		Created
*	22.08.97	Martin Kift		Added frequency param
*
*%%%**************************************************************************/

MR_VOID	ShakeCamera(CAMERA*	camera,
					MR_LONG	amp,
					MR_LONG	duration,
					MR_LONG	freq)
{
	MR_LONG	angle;


	MR_ASSERT(camera);

	// Make shake primarily in Y direction
	angle 						= (rand() & 0x1ff) - 0x100;
	camera->ca_shake_amp_y 		= (rcos(angle) * amp) >> 8;
	camera->ca_shake_amp_x 		= (rsin(angle) * amp) >> 8;
	camera->ca_shake_duration	= duration;
	camera->ca_shake_timer		= duration;
	camera->ca_flags 			|= CAMERA_FLAG_SHAKING;

	// Make y freq some value in the range of x freq to make shake slightly random
	camera->ca_shake_freq_x		= freq;
	camera->ca_shake_freq_y		= freq + (rand()%(freq>>3));

}


/******************************************************************************
*%%%% SetupCameraYRotation
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SetupCameraYRotation(
*						CAMERA*	camera)
*
*	FUNCTION	Work out which Y quadrant camera is nearest.  Set up structure
*				to rotate camera smoothly to that quadrant
*
*	INPUTS		camera	-	ptr to CAMERA to rotate
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	02.07.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	SetupCameraYRotation(CAMERA*	camera)
{
	MR_MAT*	matrix;
	MR_LONG	theta, rootp, rootn, d;
	MR_VEC	vec, normal;


	MR_ASSERT(camera);
	matrix = &camera->ca_mod_matrix;

	if (matrix->m[2][2] > 0xb50)
		{
		// Quadrant 0
		rootp 	= 0x0000;
		rootn 	= 0x1000;
		d		= FROG_DIRECTION_N;
		}
	else
	if (matrix->m[2][2] < -0xb50)
		{
		// Quadrant 2
		rootp 	= 0x800;
		rootn 	= 0x800;
		d		= FROG_DIRECTION_S;
		}
	else
	if (matrix->m[0][2] > 0xb50)
		{
		// Quadrant 1
		rootp 	= 0x400;
		rootn 	= 0x400;
		d		= FROG_DIRECTION_E;
		}
	else
		{
		// Quadrant 3
		rootp 	= 0xc00;
		rootn 	= 0xc00;
		d		= FROG_DIRECTION_W;
		}

	camera->ca_mod_matrix_dest_ytheta = 0;
	vec.vx 	= matrix->m[0][2];
	vec.vy 	= matrix->m[1][2];
	vec.vz 	= matrix->m[2][2];
	theta	= MR_VEC_DOT_VEC(&vec, &Frog_fixed_vectors[d]) >> 12;
	theta	= MR_ACOS(theta);

	MROuterProduct12(&Frog_fixed_vectors[d], &vec, &normal);
	if (normal.vy > 0)
		{
		camera->ca_mod_matrix_dest_ytheta 		= rootp;
		camera->ca_mod_matrix_current_ytheta 	= rootp + theta;
		camera->ca_mod_matrix_delta_ytheta 		= -CAMERA_MOD_MATRIX_DELTA_YTHETA;
		}
	else
	if (normal.vy < 0)
		{
		camera->ca_mod_matrix_dest_ytheta 		= rootn;
		camera->ca_mod_matrix_current_ytheta 	= rootn - theta;
		camera->ca_mod_matrix_delta_ytheta 		= CAMERA_MOD_MATRIX_DELTA_YTHETA;
		}
	else
		camera->ca_mod_matrix_delta_ytheta = 0;
}


/******************************************************************************
*%%%% CreateCameraMatrix
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	CreateCameraMatrix(
*						CAMERA*	camera,
*						MR_VEC*	target)
*
*	FUNCTION	Create camera matrix from its current position and target
*				position.  Calculate roll
*
*	INPUTS		camera	-	ptr to CAMERA whose matrix we want to create
*				target	-	point to look at
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.07.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	CreateCameraMatrix(	CAMERA*	camera,
							MR_VEC*	target)
{
	MR_MAT*	matrix;


	matrix 	= camera->ca_matrix;

	// Roll vector is world Y
	MRPointMatrixAtVector(matrix, target, &Game_y_axis_pos);
}

