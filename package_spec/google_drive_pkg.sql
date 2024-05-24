create or replace package google_drive_pkg as

  type event_rt is record (
    location     varchar2(2000),
    year         varchar2(2000),
    event_name   varchar2(2000),
    created_time timestamp
  );

  type events_ntt is table of event_rt;

  type folder_rt is record (
    id           varchar2(500),
    name         varchar2(500),
    parent_id    varchar2(500),
    created_time timestamp
  );
    
  type folders_ntt is table of folder_rt;

  type call_result is record (
    is_success      boolean,
    folders_nt      folders_ntt,
    parent_id_expr  varchar2(32000),
    code_unit       varchar2(500),
    error_message   varchar2(4000)
  );

  procedure p_get_before_and_after_images(
    pi_image_folder in varchar2
  );

  function f_get_file_list_for_counts(
    pi_root_folder_url in varchar2 default 'https://drive.google.com/drive/folders/16-r6rkahOyiBbEzfAdA-ilSSebmuPSPr',
    pi_year            in varchar2
  ) return events_ntt pipelined;

end google_drive_pkg;
/