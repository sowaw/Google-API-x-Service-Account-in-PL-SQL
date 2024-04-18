create or replace package body google_drive_pkg as

  function f_get_service_account_private_key
  return varchar2 
  is
    l_private_key varchar2(4000) := '-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC4sGgxy+hvyMzo\nCLbOyIEsRPtT18iXt1MkagMo9LOq6u5CuXZgPy3jZ0TGObBV/JX9vNbZL0Ov6iFZ\nnIzAzExp0Js0VwEm4kjCUr4m3jv25k+x9fwITuy5PUj/98x5xsG/OIjcntyaScUM\n51FD9H4K4RdPawwZEM3tkNvarL2bPoLp9ThJQwKnWzWwoBqigfZ+AxRZBJf7xFzK\nlWeyectobxxhS0aTvTVxFQLIGl2Ud2ULxaOwtdRCI41nIY8FqWPBcc9+0B4G/Ho9\nLRe2cyFsZn1MgvZu2i5EhrFSVEm3S/EpelqRkdmpFWmo//dyKvrcnEXU7pN2lOTP\nGZcKey1vAgMBAAECggEAGIHsKaN1whOiwS2a2IC5x16V/S+2og9FHKFmrvIdv1Hy\ncO88WpQ3qiPjd+xizl44pxV+aw5/DGJkr4f7E4BoqWfxmHXtJLRFVGf3bJ/z1BUG\nwUYzfgS/G+uaesDupMAvqIi/fIsmGeEtIUO2wG46pYXt+m9piQ/2S4575h4jAO0F\n4zEJo2JBpb0BrffyiRTt3rSuIvOyZW7cE2m26Wq5oG3MXgzOt6Q2Cgf1uBaK1DU/\nP30nbpc/0jQEww6yk1NfFP2NfBBcZ/d/vR6IDWWsqXX+uxfDo6RHjZLI6KnKRl8B\nGoOZHo4a2bACZ5//Z4t5oGU/u6XmFwKPEFSf4LAJDQKBgQD5HTLB9zqbdjugyU8S\nIfMIhPaZhdQ5GBDReoGB5UCPCVcVcqEVMXo1PYVVDMI4xcfsXxIomMbgDORVsC+V\nYCaZm7INTcbqk55RyXLknvWTeW0BvbJAT//7jGFe7WCvIin2lLnZHbfbwZb7ZI3b\ntRhQvQXqTbLqUuucmzoADP2+fQKBgQC9y1HEY9hrblVWFeHg5Mcvc6clqNGwy2D1\nQ4OlazVoYByUw8yY15Xj8wj7T9yVeHoACMiH3KvPeMuPZ9WI9eP6om0SBYhL8on7\n3bUwsdoh7PM09w1jo/Rn+bUBSCf9MTM+lI4AmgojlwRSovxnMwu2W7smcQEPIH4N\nK3Lm29EDWwKBgQCQEun7MlAr/0pnKGZZt1bG05eHnNXrm1aGwJJMHNmkoCNEXUJ6\nbl4ekpEdaj6d9Q02UJnA7vL+O5aHVFmAy9YnOtvUQ+pKWsvSw252eNTQ0QZRXnPM\nLDiBNGRQMXucbmbUnJmLz1s5dpIqnLJKokcI0vmr0/oo+YIY1dHKm7jZRQKBgQCM\n9Y67D3TTBVT35LSoNQICqiDABYwHhGV0gzopB2DZLljL3Ef+VE+MxxoqnHu1v47M\nq7lTvn8UTiDRV0rut8EkirH7KoS5816r41QI4G6jt7pB4iLdmA2Tk4/tbcvVbk8i\n8W4t4DobiLO7NDXF59GRFLwApvkkZPt5iIWEFEo99QKBgFg2hnDDNmuCpeZMCFal\n75USIAeqd4R97xuTGL9XHczUBx1cjQsqeA29wfW/JJ11GdUgIJIaQBdO1ADfwIjB\nPYnZdR91TqGWVXLIZbN0lMqRz5f7SdPotGwOmkqJBNI2Dg4S/XwFgssRK1WdCYLw\nsvNsA2Cf/CoqXAB/eNFNW7rq\n-----END PRIVATE KEY-----\n';
  begin
    return replace(l_private_key, '\n', '');
  exception
    when others then
      raise;
  end f_get_service_account_private_key;

  function f_extract_folder_id_from_url(pi_url in varchar2)
  return varchar2 
  is
  begin
    return regexp_substr(pi_url, '\w{25,}');
  exception
    when others then
      raise;
  end f_extract_folder_id_from_url;

  function f_get_access_token
  return varchar2
  is
    c_google_api_service_account_email constant varchar2(4000) := 'rewild-earth-service-account@rewildearth.iam.gserviceaccount.com';
    c_google_api_scopes                constant varchar2(4000) := 'https://www.googleapis.com/auth/drive.metadata.readonly';
    c_google_api_token_endpoint        constant varchar2(4000) := 'https://oauth2.googleapis.com/token';
    c_google_api_token_request_url     constant varchar2(4000) := 'https://oauth2.googleapis.com/token?grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer' || chr(38) ||'assertion=';

    l_current_token varchar2(500);

    l_jwt_header        varchar2(4000);
    l_jwt_header_base64 varchar2(4000);
    l_jwt_claim         varchar2(4000);
    l_jwt_claim_base64  varchar2(4000);

    l_private_key       varchar2(4000);

    l_sign              varchar2(1000);
    l_signature         varchar2(1000);
    l_full_jwt_base64   varchar2(4000);

    l_token_request_url varchar2(4000);
    l_clob              clob;
  begin
    -- 1st step - get current token from apex colletion or any other place where you will store it
    -- l_current_token := f_get_current_access_token;

    if l_current_token is null then
      l_jwt_header := '{"alg":"RS256", "typ":"JWT"}';
      l_jwt_claim  := '{' ||
                      '"iss":"' || c_google_api_service_account_email || '"' ||
                      ',"scope":"' || c_google_api_scopes || '"' ||
                      ',"aud":"' || c_google_api_token_endpoint || '"' ||
                      ',"exp":' || to_char( round( ( cast(sys_extract_utc(systimestamp) as date) - to_date('1970-01-01 00:00:00', 'yyyy-mm-dd hh24:mi:ss') ) * 24 * 60 * 60 ) + 3600  ) ||
                      ',"iat":' || to_char( round( ( cast(sys_extract_utc(systimestamp) as date) - to_date('1970-01-01 00:00:00', 'yyyy-mm-dd hh24:mi:ss') ) * 24 * 60 * 60 )  ) ||
                      '}';

      l_jwt_header_base64 := as_crypto.base64url_encode(p_txt => l_jwt_header);
      l_jwt_claim_base64  := as_crypto.base64url_encode(p_txt => l_jwt_claim);     

      l_private_key := f_get_service_account_private_key;

      l_sign := as_crypto.sign(src        => utl_raw.cast_to_raw(c => l_jwt_header_base64 || '.' || l_jwt_claim_base64),
                               prv_key    => utl_raw.cast_to_raw(c => l_private_key),
                               pubkey_alg => as_crypto.key_type_rsa,
                               sign_alg   => as_crypto.sign_sha256_rsa);

      l_signature := as_crypto.base64url_encode(p_raw => l_sign);

      l_full_jwt_base64 := l_jwt_header_base64 || '.' || l_jwt_claim_base64 || '.' || l_signature;

      -- request access token
      apex_web_service.g_request_headers.delete;
      apex_web_service.g_request_headers(1).name := 'Content-Type';
      apex_web_service.g_request_headers(1).value := 'application/x-www-form-urlencoded';    
      apex_web_service.g_request_headers(2).name := 'Content-Length';
      apex_web_service.g_request_headers(2).value := 0;

      l_clob := apex_web_service.make_rest_request(
        p_url         => c_google_api_token_request_url || l_full_jwt_base64,
        p_http_method => 'POST'
      );

      -- TODO read the status code property and decide how to handle the error
      apex_json.parse(l_clob);

      -- TODO save token in collection or any other place to store it
      -- Then return those new values
      return apex_json.get_varchar2('token_type') || ' ' || apex_json.get_varchar2('access_token');       
    end if;
  exception
    when others then
      raise;
  end f_get_access_token;

  procedure p_list_images_by_parent_folder(pi_folder_id in varchar2)
  is
    l_access_token       varchar2(4000);
    l_clob               clob;
    l_list_files_api_url varchar2(4000);

    c_collection_name    constant varchar2(50) := 'GOOGLE_DRIVE_API_OUTPUT';

    cursor cur_images_from_google_api(p_clob clob) is
      select id,
             'https://drive.google.com/thumbnail?id=' || id || chr(38) || 'sz=w300' as thumbnail_url,
             name,
             sequence_number,
             lower_name
        from (
          select api_row.id,
                 regexp_substr(api_row.name, '^\d+') as sequence_number,
                 api_row.name,
                 lower(name)                         as lower_name 
            from dual,
                 json_table(p_clob, '$.files[*]'
                  columns(
                    id   varchar2(500) path '$.id',
                    name varchar2(500) path '$.name'
                  )) api_row
           -- limit results to names starting with some digits
           where regexp_instr(api_row.name, '^\d+') > 0 
        )
        where (lower_name like sequence_number || ' begin%' or
               lower_name like sequence_number || ' end%')
        order by sequence_number,
                 case
                   when lower_name like '%begin%' then 1
                   else 2
                 end
      ;        
  begin
    -- get access token
    l_access_token := f_get_access_token;

    -- call the api to list files
    apex_web_service.g_request_headers.delete;
    apex_web_service.g_request_headers(1).name := 'Authorization';
    apex_web_service.g_request_headers(1).value := l_access_token;

    l_list_files_api_url := 
      'https://www.googleapis.com/drive/v3/files?' ||
      chr(38) ||
      'q=''' || pi_folder_id || ''' in parents and trashed=false' ||
      chr(38) ||
      'fields=files(id,name)'
      ;

    l_clob := apex_web_service.make_rest_request(
      p_url         => l_list_files_api_url,
      p_http_method => 'GET'
    );

    dbms_output.put_line('status code: ' || apex_web_service.g_status_code);
    dbms_output.put_line('reason phrase: ' || apex_web_service.g_reason_phrase);
    dbms_output.put_line('clob: ' || l_clob);

    -- dbms_output.put_line(l_clob);

    -- TODO handle the status code before the api call

    -- TODO what it returns the result even if the resource is not shared yet

    -- TODO open the cursor fetch the %found property and depending on, create the collection

    apex_collection.create_collection(
      p_collection_name    => c_collection_name,
      p_truncate_if_exists => 'YES'
    );

    -- transform data got from api and load into apex collection
    for rec in cur_images_from_google_api(p_clob => l_clob) loop
      dbms_output.put_line(rec.id);
      dbms_output.put_line(rec.name);
      dbms_output.put_line(rec.thumbnail_url);

      apex_collection.add_member(
        p_collection_name => c_collection_name,
        p_c001            => rec.name,
        p_c002            => rec.thumbnail_url
      );
    end loop;

    -- TODO test solution in APEX context
  exception
    when others then
      raise;
  end p_list_images_by_parent_folder;

  procedure p_get_before_and_after_images(pi_image_folder in varchar2)
  is
    l_parent_folder_id varchar2(50);
    l_access_token     varchar2(4000);
  begin
    -- extract folder id from the passed URL
    l_parent_folder_id := f_extract_folder_id_from_url(pi_url => pi_image_folder);

    -- call the api
    p_list_images_by_parent_folder(pi_folder_id => l_parent_folder_id);
  exception
    when others then 
      raise;
  end p_get_before_and_after_images;

end google_drive_pkg;
/