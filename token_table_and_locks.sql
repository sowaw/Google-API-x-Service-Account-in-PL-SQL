-- 1. create table
create table google_access_token (
  id                      number primary key,
  token_hex               varchar2(4000),
  key_bytes_hex           varchar2(4000),
  is_locked_to_refresh_yn varchar2(1)    not null,
  updated_user            varchar2(100)  default nvl(sys_context('APEX$SESSION', 'APP_USER'), user) not null,
  updated_date            date           default sysdate not null 
);

-- 2. insert the only row (it will be updated only)
insert into google_access_token (
  id,
  token_hex,
  key_bytes_hex,
  is_locked_to_refresh_yn
) values (
  1,
  null,
  null,
  'N'
);
commit;

set serveroutput on;
-- a) user A changes the flag, does sth and changes flag back again
declare
  l_google_access_token_row google_access_token%rowtype;
begin
  select *
    into l_google_access_token_row
    from google_access_token
   where id = 1;

  if l_google_access_token_row.is_locked_to_refresh_yn = 'N' then
    update google_access_token
       set is_locked_to_refresh_yn = 'Y'
     where id = 1;
    
    commit; -- this must happen because other db sessions should see that
    
    dbms_output.put_line('I am starting to sleep now.'); 
    dbms_session.sleep(seconds => 10);
    -- DO YOU STUFF HERE
    -- THIS PART CAN RAISE SOME EXCEPTIONS HERE SO REMEMBER TURN THE ROW BACK TO PREVIOUS STEP (N)

    update google_access_token
       set is_locked_to_refresh_yn = 'N'
     where id = 1;

    commit; -- this must happen because other db sessions should see that
  else
    dbms_output.put_line('Row is locked by other user now. Try again in a moment.'); 
  end if;
end;
/