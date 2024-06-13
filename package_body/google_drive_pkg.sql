create or replace package body google_drive_pkg as

-- CONSTANTS
  c_encryption_type constant pls_integer := dbms_crypto.encrypt_aes256 + 
                                            dbms_crypto.chain_cbc + 
                                            dbms_crypto.pad_pkcs5;  

-- EXCEPTIONS

  -- when access token request fails
  e_token_endpoint_call_error exception;
  pragma exception_init(e_token_endpoint_call_error, -20001);

  -- when Google API request returns code other than 200 and 401 (unathorized)
  e_api_endpoint_call_error exception;
  pragma exception_init(e_api_endpoint_call_error, -20002);  

  -- it was tried to call Google Drive API twice and both attempts fails (there is no infinite loop)
  e_api_endpoint_call_failed exception;
  pragma exception_init(e_api_endpoint_call_failed, -20003);

  -- regular expression extracting the folder id from the URL gives NULL
  e_folder_id_from_url_is_empty exception;    
  pragma exception_init(e_folder_id_from_url_is_empty, -20004);

  -- when the GOOGLE_ACCESS_TOKEN table is empty (one update-only row is expected)
  e_no_row_in_token_table exception;
  pragma exception_init(e_no_row_in_token_table, -20005);

  -- when token request is in progress
  e_token_request_in_progress exception;
  pragma exception_init(e_token_request_in_progress, -20006);

  -- an issue occurred during getting data for year counts
  e_getting_counts_error exception;
  pragma exception_init(e_getting_counts_error, -20007);

-- PRIVATE PROCEDURES AND FUNCTIONS

  procedure p_add_apex_error(pi_message in varchar2)
  is
  begin
    apex_error.add_error(
      p_message          => pi_message,
      p_display_location => apex_error.c_inline_in_notification
    );
  exception
    when others then
      apex_debug.error(
        p_message => 'Error in code unit: %s. %s',
        p0        => 'p_add_apex_error',
        p1        => sqlerrm
      );

      raise;
  end p_add_apex_error;

  function f_get_service_account_private_key
  return varchar2 
  is 
    c_key_bytes_hex   constant varchar2(200) := '7B4F50DFD16C6DDAEC808CB114B6C9FDA13D9E82482E4CACA5256BFBF8D8E69F';

    c_private_key_hex constant varchar2(4000) := '22B5A9D51D2F9FE1AC036591128585C3409FAA3EA31A1CD9BDF81B9A146882FC9F0A5A426671D30AA5BDBC83DC3403DB19496370E5C3E03E5DC6AF7B541832D9C7961793F6307C77C72F96840DFC1B3E9128FC95798321BF791C0B3845E4BA1A1EB9EA66ABAE7425D9B7B6ECF6EF05A822214B029255297846C9056478E983DB4CD3D82F9CF61B4221D273ED638185851DFAE8FE72CB396F0CCA3C5DBC5B07B12BAEC4A5D4ECC5A00EEA92642C84E8ED0C73E425C7F7170AC3FABF6EBB7F611C70913BB03180BA79BECEC75EFB7294EC6F286E1E866E569C024B8FA3909ABF0B004A114D9FC97A75877C223325886A6FEE0D733913575A2B480674EBC52E8D11E8C287C7F2F223FDE2D5B68984FA76424A49272ED74AD1BA766FCFB271C8653BEC71F613B0D94278D26DF8868D80D92D6133F317C6C4CAD171ACE7C897271E6D91BF37AA465D9F821E578D5E14A0A4102FFDCDBBA929B73395E021A6C0BAAF8DD49DAE945339F36D8A3C521BD136BFF2CE4888CF2726FD02AD29DFA7B572A2619D4A2F2DD2D545F42C57E5B1AB2E9FBF1EF3377E25F117E1625DDAEE094642751D8BCA582BEDE2E88AF78E05D948F5974167B29011681CB6E5AB4960DF9666BD48BB24A9F5C221A4336F0D8E025884D93632E20642485A22E8EB23329175A28F99D5D0606A416ACBD625C385DD4BEEE60B3ADC66AADBFA3DDC54F4271D73180364EF52009F0E6394B2F73C63F06162ED1286807C8F3082C16D6320A30BF3B37B2E95C4C6B1FF65E8433D26694D176135A3BC3BD5FED492CCE246B1BE052ED2E8DBD06BF9642BB64B19FBBCE7687E35257799C52D4D0D542BEB1F26151C2194F32F43B196C72D5296F9B8A3C2E59F7989658416DB6BCF59C39FA243FE8A37DD61CE93193F0E5B5B94FDBF9A18D88705C72D9D1F7EF8C37EE45D2F309AA385F1C6F3CD603A3996118CD9DC5E795C1964DFC00C30F5D0738C81100BF95A3355398DB237E6DA526CE148D696650446F530857DAE2BBD6D178B1491D1820CA849CFD9DFF668D7F405F7C75C403DFFDDAD1B9E9A182C1B69B4FD409C30579B10510D7ECFB8F31859E3B93A1A31EBA204884C0E4A5E45B63F16990A4320E20D42C390ADEE5C5630353D9AB0FCA850B9218A569FC40BA99D303824E5502AA0438C9A3568EE8B142A98F0F738F1C3A8D0ADA181ED7DFF3CB25EC68C114EF429822F701182C3D98EB18E25AEC8E989DCB10C09A854733D18169713BA70EBC5929911B7140C3360A72DE4D20E234A55099AD138E04B853D718488EFE90319FC8C53F0BD82CCE061A08FEE5E8325E0BDFCCBCE44C56D4E5051BEE174223BBA32939DACC5E42D872F2CCD60074D64D324F7FAD59EAD1E00A8D4E6142C82696D54A4FEB2D335E5B4EA21CE529D2E53F7FC89289F49676414A25D6D67A3C0875CBD7A8A24E1FA0ED7D297B2E87B80807E566592733E5E1A50B387A412580B0984FF6CE3666DF6152718BFF16A024EFAB754A1669DD025484324C1B3FFC3E2374989094B40FB18400EF343D19242393E3EE9428935FBF23E2B61C3E32D397CFC48022B22BBF1341F88A0159664DA63F0D3305A316AB31DCFDA9D81B39BC7F1062366D1E4E30B8BFE0A9299255A3B0639C2A719089838528BF5C82C50C231AEFF20E176C714264A3BBEC784784BFC662EE8C5699A0A38C87D161A4C9667E409EBB2E08401D11D8C142E82445C913088BE27B1D909458510BAF6926206CEA64FCF8266B2606E6CCEE95C315582DE0A518E64CDDC6882F77A7AC147AB332FE02E47561872C34CC8959EA7667966B37B34AE7D89E7A8575F2DA67771F2D7E5A5053C918516C7DA9B13630F7E7289A4EA4EB3799133045168E85D84141E3B2082A26106F1E5AA3F5CEC0B244BEADE7F73856EE20DAF3B1E86CDC2AAE5344E11EEC2DB49F28FE670243E3B2030709B05C5BAB20FC6593D97E8B41681B991E22084A31C9557FCF6A08324CBD3BA1C0BFCFA7D8615416E19E4868C291FA649EDC285B66883C257E9B3CF6086CC06AB7C005971F905B13502E622161AF0BA84EAF87762E440365373F4C3028E1F7D615D9EB6B1A7D17E317FDB1EB076A083CFC6C06275149775593EF78859712C9556EB81192E7CCBE45ACE190DB5D70330CF958A74EC664186EF9FDDAF22FA1FAE4C3DD98A604DE2520AD9055AB6E1AEF61B2D32E7ED31195CB31AF73E4BDC46D075659ECD50D6A2D201A6F6A544D46C7DD1F1F8AF1896329FB057C33BBF5210675CD06A28FCD88D15503F2C06C52744C3C5ED3F5EB8938ADF36D7F62F540C6E7ECD8DB30B6FF1D7BF77419530B86582AEBF5DAFB3328B0B92F238860050C191152EA3C20946C86122BC04B4D87F25B0674D9628ACC6D83CB34CD0C7CC79E5ECC047987760215C9CEC1F371BE129158D32970FC986D35AFAED1E4BBD0EE2E6DFDB70E406F7650CD914478E564FDC2D';

    l_return        varchar2(4000);
    l_decrypted_raw raw(4000);
    l_output_string varchar2(4000);
  begin
    l_decrypted_raw := dbms_crypto.decrypt(
      src => hextoraw(c_private_key_hex),
      typ => c_encryption_type,
      key => hextoraw(c_key_bytes_hex)
    );

    l_output_string := utl_i18n.raw_to_char(
      data        => l_decrypted_raw,
      src_charset => 'AL32UTF8'
    );

    l_return := replace(l_output_string, '\n', '');

    return l_return;
  exception
    when others then
      apex_debug.error(
        p_message => 'Error in code unit: %s. %s',
        p0        => 'f_get_service_account_private_key',
        p1        => sqlerrm
      );    

      raise;
  end f_get_service_account_private_key;

  function f_extract_folder_id_from_url(pi_url in varchar2)
  return varchar2 
  is
    l_return varchar2(200);
  begin
    l_return := regexp_substr(pi_url, '(\w|-){25,}');
    
    return l_return;
  exception
    when others then
      apex_debug.error(
        p_message => 'Error in code unit: %s. %s',
        p0        => 'f_extract_folder_id_from_url',
        p1        => sqlerrm
      );   

      raise;
  end f_extract_folder_id_from_url;

  procedure p_store_access_token(pi_access_token in varchar2)
  is
    l_key_bytes_raw raw(32);
    l_num_key_bytes number := 256/8;
    l_input_raw     raw(4000);
    l_encrypted_raw raw(4000);
    l_encrypted_hex varchar2(4000);
  begin
    -- initial setup
    l_key_bytes_raw := dbms_crypto.randombytes(number_bytes => l_num_key_bytes);

    -- translate input string to raw used by dbms_crypto
    l_input_raw := utl_i18n.string_to_raw(
      data        => pi_access_token,
      dst_charset => 'AL32UTF8'
    );

    -- run the encryption
    l_encrypted_raw := dbms_crypto.encrypt(
      src => l_input_raw,
      typ => c_encryption_type,
      key => l_key_bytes_raw
    );

    update google_access_token
       set token_hex     = rawtohex(l_encrypted_raw),
           key_bytes_hex = rawtohex(l_key_bytes_raw),
           updated_date  = sysdate
     where id = 1;

  exception
    when others then
      apex_debug.error(
        p_message => 'Error in code unit: %s. %s',
        p0        => 'p_store_access_token',
        p1        => sqlerrm
      );    

      raise;
  end p_store_access_token;

  function f_get_access_token_from_storage
  return varchar2 
  is
    l_return varchar2(4000);
    l_google_access_token_row google_access_token%rowtype;

    l_decrypted_raw raw(4000);
  begin
    select *
      into l_google_access_token_row
      from google_access_token
     where id = 1;

    if l_google_access_token_row.token_hex is null then
      -- there is nothing to decrypt, new access token has to be requested anyway
      l_return := null;
    else
      l_decrypted_raw := dbms_crypto.decrypt(
        src => hextoraw(l_google_access_token_row.token_hex),
        typ => c_encryption_type,
        key => hextoraw(l_google_access_token_row.key_bytes_hex)
      );

      l_return := utl_i18n.raw_to_char(
        data        => l_decrypted_raw,
        src_charset => 'AL32UTF8'
      );
    end if;
    
    return l_return;
  exception
    when no_data_found then 
      raise e_no_row_in_token_table;
    when others then
      apex_debug.error(
        p_message => 'Error in code unit: %s. %s',
        p0        => 'f_get_access_token_from_storage',
        p1        => sqlerrm
      );

      raise;
  end f_get_access_token_from_storage;

  procedure p_lock_token_row
  is
  begin
    update google_access_token
       set is_locked_to_refresh_yn = 'Y',
           updated_date            = sysdate
     where id = 1;

    commit;

  exception
    when others then
      apex_debug.error(
        p_message => 'Error in code unit: %s. %s',
        p0        => 'p_lock_token_row',
        p1        => sqlerrm
      );

      raise;    
  end p_lock_token_row;

  procedure p_unlock_token_row
  is
  begin
    update google_access_token
       set is_locked_to_refresh_yn = 'N',
           updated_date            = sysdate
     where id = 1;

    commit;

  exception
    when others then
      apex_debug.error(
        p_message => 'Error in code unit: %s. %s',
        p0        => 'p_unlock_token_row',
        p1        => sqlerrm
      );

      raise;    
  end p_unlock_token_row;  

  function f_get_access_token(pi_must_get_new_token boolean default false)
  return varchar2
  is
  pragma autonomous_transaction;
    c_google_api_service_account_email constant varchar2(4000) := 'rewild-earth-service-account@rewildearth.iam.gserviceaccount.com';
    c_google_api_scopes                constant varchar2(4000) := 'https://www.googleapis.com/auth/drive.metadata.readonly';
    c_google_api_token_endpoint        constant varchar2(4000) := 'https://oauth2.googleapis.com/token';
    c_google_api_token_request_url     constant varchar2(4000) := 'https://oauth2.googleapis.com/token?grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer' || chr(38) ||'assertion=';

    l_current_token     varchar2(4000);

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

    l_return            varchar2(4000);

    l_google_access_token_row google_access_token%rowtype;
  begin
    -- 1st step - get current token from apex colletion or any other place where you will store it
    if not pi_must_get_new_token then
      l_current_token := f_get_access_token_from_storage;
    end if;

    -- 2nd step - if there was a token in storage, and there is no request to generate a new one, 
    -- just grab the existing token
    if l_current_token is not null and not pi_must_get_new_token then
      -- reuse the stored token
      l_return := l_current_token;
    else
      select *
        into l_google_access_token_row
        from google_access_token
       where id = 1;

      if l_google_access_token_row.is_locked_to_refresh_yn = 'N' then
        -- lock the row to allow token request for one session only
        p_lock_token_row;

        -- do the token request part
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

        if apex_web_service.g_status_code = 200 then
          apex_json.parse(l_clob);

          -- return new values
          l_return := apex_json.get_varchar2('token_type') || ' ' || apex_json.get_varchar2('access_token'); 

          -- save token in collection or any other place to store it
          p_store_access_token(pi_access_token => l_return);
          -- unlock the row with token
          p_unlock_token_row;

        else
          -- there is a problem with token request
          raise e_token_endpoint_call_error;
        end if;        
        ------------------------------
      else
        -- cannot make a token request - the row is already locked by other session
        raise e_token_request_in_progress;
      end if;
    end if;

    return l_return;
  exception
    when others then
      apex_debug.error(
        p_message => 'Error in code unit: %s. %s',
        p0        => 'f_get_access_token',
        p1        => sqlerrm
      );   

      p_unlock_token_row;

      raise;
  end f_get_access_token;

  function f_list_images_by_parent_folder(pi_folder_id in varchar2)
  return boolean
  is
    l_access_token       varchar2(4000);
    l_clob               clob;
    l_list_files_api_url varchar2(4000);

    l_return             boolean := false;

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
                --  lower_name
                 case
                   when lower_name like '%begin%' then 1
                   else 2
                 end,
                 lower_name
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
      'fields=incompleteSearch,nextPageToken,files(id,name)'
      ;

    l_clob := apex_web_service.make_rest_request(
      p_url         => l_list_files_api_url,
      p_http_method => 'GET'
    );

    if apex_web_service.g_status_code = 200 then
      apex_collection.create_collection(
        p_collection_name    => c_collection_name,
        p_truncate_if_exists => 'YES'
      );

      -- transform data got from api and load into apex collection
      for rec in cur_images_from_google_api(p_clob => l_clob) loop
        apex_collection.add_member(
          p_collection_name => c_collection_name,
          p_c001            => rec.name,
          p_c002            => rec.thumbnail_url
        );
      end loop;

      l_return := true;
    elsif apex_web_service.g_status_code = 401 then
      -- current access token is not valid anymore, so we try to repeat this function
      -- so get the new token. this function will also save it in its storage
      l_access_token := f_get_access_token(pi_must_get_new_token => true);

      l_return := false;
    else
      raise e_api_endpoint_call_error;
    end if;

    return l_return;

  exception
    when others then
      apex_debug.error(
        p_message => 'Error in code unit: %s. %s',
        p0        => 'f_list_images_by_parent_folder',
        p1        => sqlerrm
      );    

      raise;
  end f_list_images_by_parent_folder;

  function f_get_files_by_parents (
    pi_parents_expression in varchar2,
    pi_access_token       in varchar2,
    pi_name_contains_phrase in varchar2 default null,
    pi_limit_to_folders   in boolean default true
  )
  return call_result
  is
    l_clob                      clob;
    l_list_files_api_url        varchar2(32000);
    l_list_files_api_target_url varchar2(32000);
    l_parents                   apex_t_varchar2;
    l_created_time_tmstp        timestamp;
    l_return                    call_result;
    l_element_counter           number := 0;

    l_incomplete_call boolean;
    l_next_page_token varchar2(4000);
  begin
    apex_web_service.g_request_headers.delete;
    apex_web_service.g_request_headers(1).name  := 'Authorization';
    apex_web_service.g_request_headers(1).value := pi_access_token;

    l_incomplete_call   := true;
    l_next_page_token   := null;
    l_return.folders_nt := folders_ntt();

    l_list_files_api_url := 
      'https://www.googleapis.com/drive/v3/files?' ||
      chr(38) ||
      'q=(' || pi_parents_expression || ') and trashed=false' || 
            case 
        when pi_name_contains_phrase is not null then
           ' and name contains ''' || trim(pi_name_contains_phrase) || ''''
        else
          null
      end ||
      case 
        when pi_limit_to_folders then 
        ' and mimeType=''application/vnd.google-apps.folder'''
      else 
        null 
      end ||
      chr(38) ||
      'fields=incompleteSearch,nextPageToken,files(id,name,parents,createdTime,webViewLink)' ||
      chr(38) ||
      'pageSize=1000'
      ;

    logger.log(l_list_files_api_url);

    while l_incomplete_call loop
      l_list_files_api_target_url := 
        case
          when l_next_page_token is not null then
            l_list_files_api_url || chr(38) || 'pageToken=' || l_next_page_token
          else
            l_list_files_api_url
        end;

      l_clob := apex_web_service.make_rest_request(
        p_url         => l_list_files_api_target_url,
        p_http_method => 'GET'
      );
      
      if apex_web_service.g_status_code = 200 then
        apex_json.parse(l_clob);

        l_return.folders_nt.extend(apex_json.get_count(p_path => 'files'));

        for i in 1..apex_json.get_count(p_path => 'files') loop
          l_parents := apex_json.get_t_varchar2('files[%d].parents', i);

          l_created_time_tmstp := to_timestamp(apex_json.get_varchar2('files[%d].createdTime', i), 'yyyy-mm-dd"T"hh24:mi:ss.FF3"Z"');

          l_return.folders_nt(l_element_counter + i) := folder_rt(
            apex_json.get_varchar2('files[%d].id', i),
            apex_json.get_varchar2('files[%d].name', i),
            l_parents(l_parents.first),
            l_created_time_tmstp,
            apex_json.get_varchar2('files[%d].webViewLink', i)
          );

        end loop;

        l_element_counter := l_element_counter + apex_json.get_count(p_path => 'files');

        l_next_page_token := apex_json.get_varchar2('nextPageToken');
        l_incomplete_call :=
          case
            when l_next_page_token is not null then
              true
            else
              false
          end;

      else -- non-200 http status code
        l_return.is_success := false;
        l_return.code_unit   := 'Error when getting event folders from Google Drive API.';
        l_return.error_message := substr(l_clob, 1, 4000);

        return l_return;
      end if;              

    end loop;

    l_return.is_success := true;

    return l_return;

  exception
    when others then
      apex_debug.error(
        p_message => 'Error in code unit: %s. %s',
        p0        => 'f_get_files_by_parents',
        p1        => sqlerrm
      );

      l_return.is_success := false;
      l_return.code_unit := 'f_get_files_by_parents';
      l_return.error_message := sqlerrm;

      return l_return;
  end f_get_files_by_parents;

  function f_get_filtered_location_folders(
    pi_folders_nt in folders_ntt
  ) 
  return call_result
  is
    l_return          call_result;
    l_parent_id_exprs apex_t_varchar2;
  begin
    select *
      bulk collect into l_return.folders_nt
      from table(pi_folders_nt) t
     where trim(t.name) not in 
     (
      '.Annual Summaries',
      'Resources',
      'Species',
      'Volunteer Interviews'
     );    

    l_return.is_success := true;

    return l_return;
  exception
    when others then
      apex_debug.error(
        p_message => 'Error in code unit: %s. %s',
        p0        => 'f_get_filtered_location_folders',
        p1        => sqlerrm
      );

      l_return.is_success := false;
      l_return.code_unit := 'f_get_filtered_location_folders';
      l_return.error_message := sqlerrm;

      return l_return;
  end f_get_filtered_location_folders;

  function f_get_filtered_year_folders(
    pi_folders_nt  in folders_ntt,
    pi_year        in varchar2
  ) 
  return call_result
  is
    l_return          call_result;
    l_parent_id_exprs apex_t_varchar2;
  begin
    select *
      bulk collect into l_return.folders_nt
      from table(pi_folders_nt) t
      where t.name = nvl(pi_year, t.name);

    l_return.is_success := true;

    return l_return;
  exception
    when others then
      apex_debug.error(
        p_message => 'Error in code unit: %s. %s',
        p0        => 'f_get_filtered_year_folders',
        p1        => sqlerrm
      );

      l_return.is_success := false;
      l_return.code_unit := 'f_get_filtered_year_folders';
      l_return.error_message := sqlerrm;

      return l_return;
  end f_get_filtered_year_folders;  

  function f_get_filtered_event_folders(
    pi_folders_nt in folders_ntt
  ) 
  return call_result
  is
    l_return          call_result;
    l_parent_id_exprs apex_t_varchar2;
  begin
    select *
      bulk collect into l_return.folders_nt
      from table(pi_folders_nt) t
     where regexp_like(t.name, '^[0-9]{4}-[0-9]{2}-[0-9]{2}.*');   

    l_return.is_success := true;

    return l_return;
  exception
    when others then
      apex_debug.error(
        p_message => 'Error in code unit: %s. %s',
        p0        => 'f_get_filtered_event_folders',
        p1        => sqlerrm
      );

      l_return.is_success := false;
      l_return.code_unit := 'f_get_filtered_event_folders';
      l_return.error_message := sqlerrm;

      return l_return;
  end f_get_filtered_event_folders;

  function f_get_filtered_event_files(
    pi_folders_nt in folders_ntt
  ) 
  return call_result
  is
    l_return call_result;
  begin
    select f2.id,
           f2.name,
           f2.parent_id,
           f2.created_time,
           f2.web_view_link 
      bulk collect 
      into l_return.folders_nt
      from (
        select row_number() over(partition by f1.parent_id order by f1.name) as rn,
               f1.*
          from table(pi_folders_nt) f1
         where lower(f1.name) like '%begin%' 
      ) f2
      where f2.rn = 1;   

    l_return.is_success := true;

    return l_return;
  exception
    when others then
      apex_debug.error(
        p_message => 'Error in code unit: %s. %s',
        p0        => 'f_get_filtered_event_files',
        p1        => sqlerrm
      );

      l_return.is_success := false;
      l_return.code_unit := 'f_get_filtered_event_files';
      l_return.error_message := sqlerrm;

      return l_return;
  end f_get_filtered_event_files;

  function f_get_batches_with_parent_id_exprs(
    pi_parent_call_result in call_result
  )
  return parent_id_exprs_ntt
  is
    l_floor      number;
    l_mod        number;
    l_batch_size number := 250;
    l_parent_ids apex_t_varchar2;  

    l_return     parent_id_exprs_ntt := parent_id_exprs_ntt();
  begin
    l_floor := floor(pi_parent_call_result.folders_nt.count / l_batch_size);
    l_mod   := mod(pi_parent_call_result.folders_nt.count, l_batch_size);

    for i in 0..(l_floor - 1) loop
      for j in (i * l_batch_size + 1)..(i * l_batch_size + l_batch_size) loop
        apex_string.push(
          p_table => l_parent_ids,
          p_value => '''' || pi_parent_call_result.folders_nt(j).id || ''' in parents'
        );
      end loop;

      l_return.extend();
      l_return(l_return.last) := apex_string.join(
        p_table => l_parent_ids,
        p_sep   => ' or '
      );

      l_parent_ids.delete;
    end loop;

    if l_mod <> 0 then
      for i in (l_floor * l_batch_size + 1)..pi_parent_call_result.folders_nt.count loop
        apex_string.push(
          p_table => l_parent_ids,
          p_value => '''' || pi_parent_call_result.folders_nt(i).id || ''' in parents'
        );
      end loop;

      l_return.extend();
      l_return(l_return.last) := apex_string.join(
        p_table => l_parent_ids,
        p_sep   => ' or '
      );      
    end if;

    l_parent_ids.delete;

    return l_return;
  exception
    when others then
      apex_debug.error(
        p_message => 'Error in code unit: %s. %s',
        p0        => 'f_get_batches_with_parent_id_exprs',
        p1        => sqlerrm
      );
      raise;
  end f_get_batches_with_parent_id_exprs;          


-- PUBLIC PROCEDURES AND FUNCTIONS
  procedure p_get_before_and_after_images(pi_image_folder in varchar2)
  is
    l_parent_folder_id varchar2(50);
    l_access_token     varchar2(4000);

    l_is_list_function_result_correct boolean;
  begin
    -- extract folder id from the passed URL
    l_parent_folder_id := f_extract_folder_id_from_url(pi_url => pi_image_folder);

    if l_parent_folder_id is null then
      raise e_folder_id_from_url_is_empty;
    end if;

    -- call the api - 1st attempt
    l_is_list_function_result_correct := f_list_images_by_parent_folder(pi_folder_id => l_parent_folder_id);

    -- this part will be executed when the first call took the invalid access token for this moment
    -- try to call the api - 2nd attempt
    if not l_is_list_function_result_correct then
      l_is_list_function_result_correct := f_list_images_by_parent_folder(pi_folder_id => l_parent_folder_id);
    end if;

    if not l_is_list_function_result_correct then
      apex_debug.error(
        p_message => 'Cannot call the Google API - after 2nd attempt.'
      );    
      raise e_api_endpoint_call_failed;
    end if;
  exception
    when e_token_endpoint_call_error then
      p_add_apex_error(pi_message => 'There is an error when getting the access token.');
    when e_api_endpoint_call_error then
      p_add_apex_error(pi_message => 'There is an error when calling the Google API (non 401).');
    when e_api_endpoint_call_failed then
      p_add_apex_error(pi_message => 'There is an error when calling the Google API (2nd attempt).');
    when e_folder_id_from_url_is_empty then
      p_add_apex_error(pi_message => 'There is an error when extracting the folder ID from the URL.');
    when e_no_row_in_token_table then
      p_add_apex_error(pi_message => 'There is a missing row in configuration table for access token.');
    when e_token_request_in_progress then
      p_add_apex_error(pi_message => 'Other session is requesting a new access token for Google. Try again in a moment.');
    when others then
      p_add_apex_error(pi_message => 'There is an unexpected error: ' || sqlerrm); 
      raise;
  end p_get_before_and_after_images; 

  function f_get_file_list_for_counts (
    pi_root_folder_url in varchar2 default 'https://drive.google.com/drive/folders/16-r6rkahOyiBbEzfAdA-ilSSebmuPSPr',
    pi_year            in varchar2 default null
  ) 
  return events_ntt pipelined
  is
    l_root_folder_id       varchar2(50);
    l_access_token         varchar2(4000);
    l_parents_expr         varchar2(32000);

    l_location_call_result call_result;
    l_year_call_result     call_result;
    l_event_call_result    call_result;
    l_file_call_result     call_result;

    l_code_unit            varchar2(500);
    l_error_message        varchar2(4000);

    l_parent_id_exprs_nt parent_id_exprs_ntt;
    l_call_result call_result;
  begin
    l_root_folder_id := f_extract_folder_id_from_url(pi_url => pi_root_folder_url);

    l_access_token := f_get_access_token(pi_must_get_new_token => true);

    -- STEP 1.
    -- no need to do the for-looping
    l_parents_expr := '''' || l_root_folder_id || '''' || ' in parents';

    l_location_call_result := f_get_files_by_parents(
      pi_parents_expression => l_parents_expr,
      pi_access_token       => l_access_token
    );

    if not l_location_call_result.is_success then
      l_code_unit     := l_location_call_result.code_unit;
      l_error_message := l_location_call_result.error_message;

      raise e_getting_counts_error;
    end if;

    l_location_call_result := f_get_filtered_location_folders(
      pi_folders_nt => l_location_call_result.folders_nt
    );

    if not l_location_call_result.is_success then
      l_code_unit     := l_location_call_result.code_unit;
      l_error_message := l_location_call_result.error_message;

      raise e_getting_counts_error;
    end if;    

    -- STEP 2.
    -- get folders for which locations are parents
    -- so there will be folders named YYYY
    l_parent_id_exprs_nt := f_get_batches_with_parent_id_exprs(
      pi_parent_call_result => l_location_call_result
    );

    l_year_call_result.folders_nt := folders_ntt();

    for i in 1..l_parent_id_exprs_nt.count loop
      l_call_result := f_get_files_by_parents(
        pi_parents_expression => l_parent_id_exprs_nt(i),
        pi_access_token       => l_access_token  
      );

      if not l_call_result.is_success then
        l_code_unit     := l_call_result.code_unit;
        l_error_message := l_call_result.error_message;

        raise e_getting_counts_error;
      end if;

      l_year_call_result.folders_nt := l_year_call_result.folders_nt multiset union l_call_result.folders_nt;     
    end loop;        

    l_year_call_result := f_get_filtered_year_folders(
      pi_folders_nt => l_year_call_result.folders_nt,
      pi_year       => pi_year
    );

    if not l_year_call_result.is_success then
      l_code_unit     := l_year_call_result.code_unit;
      l_error_message := l_year_call_result.error_message;

      raise e_getting_counts_error;
    end if;     

    -- STEP 3.
    -- get data about events
    l_parent_id_exprs_nt := f_get_batches_with_parent_id_exprs(
      pi_parent_call_result => l_year_call_result
    );

    l_event_call_result.folders_nt := folders_ntt();

    for i in 1..l_parent_id_exprs_nt.count loop
      l_call_result := f_get_files_by_parents(
        pi_parents_expression => l_parent_id_exprs_nt(i),
        pi_access_token       => l_access_token  
      );

      if not l_call_result.is_success then
        l_code_unit     := l_call_result.code_unit;
        l_error_message := l_call_result.error_message;

        raise e_getting_counts_error;
      end if;

      l_event_call_result.folders_nt := l_event_call_result.folders_nt multiset union l_call_result.folders_nt;     
    end loop;   

    l_event_call_result := f_get_filtered_event_folders(
      pi_folders_nt => l_event_call_result.folders_nt
    );

    if not l_event_call_result.is_success then
      l_code_unit     := l_event_call_result.code_unit;
      l_error_message := l_event_call_result.error_message;

      raise e_getting_counts_error;
    end if;

    ------------------------------------------------------------
    -- STEP 4.
    -- get files for each event to check if they comply begin-end notation
    l_parent_id_exprs_nt := f_get_batches_with_parent_id_exprs(
      pi_parent_call_result => l_event_call_result
    );

    l_file_call_result.folders_nt := folders_ntt();

    for i in 1..l_parent_id_exprs_nt.count loop
      l_call_result := f_get_files_by_parents(
        pi_parents_expression => l_parent_id_exprs_nt(i),
        pi_access_token       => l_access_token,
        pi_name_contains_phrase => 'begin',
        pi_limit_to_folders   => false  
      );

      if not l_call_result.is_success then
        l_code_unit     := l_call_result.code_unit;
        l_error_message := l_call_result.error_message;

        raise e_getting_counts_error;
      end if;

      l_file_call_result.folders_nt := l_file_call_result.folders_nt multiset union l_call_result.folders_nt;     
    end loop;

    l_file_call_result := f_get_filtered_event_files(
      pi_folders_nt => l_file_call_result.folders_nt
    );

    if not l_file_call_result.is_success then
      l_code_unit     := l_file_call_result.code_unit;
      l_error_message := l_file_call_result.error_message;

      raise e_getting_counts_error;
    end if;    

    ------------------------------------------------------------
    
    -- STEP 5.
    for rec in (
      select l.name as location,
             y.name as year,
             e.name as event_name,
             e.created_time,
             e.web_view_link,
            case
              when f.id is not null then
                'Y'
              else
                'N'
            end as has_begin_end_yn
        from table(l_location_call_result.folders_nt) l
        join table(l_year_call_result.folders_nt) y
          on l.id = y.parent_id
        join table(l_event_call_result.folders_nt) e
          on y.id = e.parent_id
        left join table(l_file_call_result.folders_nt) f
          on e.id = f.parent_id
    ) loop
      pipe row(
        event_rt(
          rec.location,
          rec.year,
          rec.event_name,
          rec.created_time,
          rec.web_view_link,
          rec.has_begin_end_yn
        )
      );
    end loop;

  exception
    when e_getting_counts_error then
      pipe row(
        event_rt(
          l_code_unit,
          l_error_message,
          null,
          null
        )
      );
    when others then
      apex_debug.error(
        p_message => 'Error in code unit: %s. %s',
        p0        => 'f_get_file_list_for_counts',
        p1        => sqlerrm
      );    
      raise;
  end f_get_file_list_for_counts;


end google_drive_pkg;
/