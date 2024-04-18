create or replace package google_drive_pkg as

  procedure p_get_before_and_after_images(pi_image_folder in varchar2);

end google_drive_pkg;
/