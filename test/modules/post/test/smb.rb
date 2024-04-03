require 'rex/post/meterpreter/extensions/stdapi/command_ids'
require 'rex'
require 'fileutils'

lib = File.join(Msf::Config.install_root, "test", "lib")
$LOAD_PATH.push(lib) unless $LOAD_PATH.include?(lib)
require 'module_test'

class MetasploitModule < Msf::Post

  include Msf::ModuleTest::PostTest
  include Msf::ModuleTest::PostTestFileSystem

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Testing SMB sessions work',
        'Description' => %q{ This module will test the SMB sessions work },
        'License' => MSF_LICENSE,
        'Author' => [ 'sjanusz-r7'],
        'Platform' => all_platforms,
        'SessionTypes' => [ 'smb' ]
      )
    )
  end

  def setup
    super
  end

  def cleanup
    super
  end

  def test_console_help
    it "should support the help command" do
      stdout = with_mocked_console(session) { |console| console.run_single("help") }
      ret = true
      ret &&= stdout.buf.include?('Core Commands')
      ret &&= stdout.buf.include?('Shares Commands')
      ret &&= stdout.buf.include?('Local File System Commands')
      ret
    end
  end

  def test_file_upload_and_download
    filename = Rex::Text.rand_text_alphanumeric(8..16)
    file_path = File.expand_path "/tmp/#{filename}"
    test_data = "SMB Test Data\r\n"
    readonly_share = 'readonly'
    modifiable_share = 'modifiable'

    if File.exist? file_path
      FileUtils.rm file_path
    end

    File.binwrite(file_path, test_data)

    it "should support uploading files" do
      stdout = with_mocked_console(session) do |console|
        console.run_single("shares -i #{modifiable_share}")
        console.run_single("upload #{file_path} #{filename}")
      end

      ret = true
      ret &&= stdout.buf.include?("#{file_path} uploaded to #{filename}")
      ret
    end

    it "should support downloading files" do
      FileUtils.rm file_path
      stdout = with_mocked_console(session) { |console| console.run_single("download #{filename} #{file_path}") }

      ret = true
      ret &&= stdout.buf.include?("Downloaded #{filename} to #{file_path}")
      ret &&= (File.binread(file_path) == test_data)
      FileUtils.rm(file_path)
      ret
    end

    it "should support deleting files" do
      stdout = with_mocked_console(session) { |console| console.run_single("delete #{filename}") }

      ret = true
      ret &&= stdout.buf.include?("Deleted #{filename}")
      ret
    end

    it "should not upload to readonly share" do
      stdout = with_mocked_console(session) do |console|
        console.run_single("shares -i #{readonly_share}")
        console.run_single("upload #{file_path} #{filename}")
      end

      ret = true
      ret &&= stdout.buf.include?("Error running command upload")
      ret &&= stdout.buf.include?("The server responded with an unexpected status code: STATUS_ACCESS_DENIED")
      ret
    end
  end

  def test_files
    modifiable_share = 'modifiable'

    it "should output files in the current directory" do
      stdout = with_mocked_console(session) do |console|
        console.run_single("shares -i #{modifiable_share}")
        console.run_single("ls")
      end

      ret = true
      ret &&= stdout.buf.include?("recursive")
      ret &&= stdout.buf.include?("text_files")
      ret
    end
  end

  def test_directories
    it "should support changing a directory" do
      folder_name = 'text_files'
      modifiable_share = 'modifiable'
      expected_file_name = 'hello_world.txt'

      stdout = with_mocked_console(session) do |console|
        console.run_single("shares -i #{modifiable_share}")
        console.run_single("cd #{folder_name}")
        console.run_single("ls")
      end

      ret = true
      ret &&= stdout.buf.include? expected_file_name
      ret
    end

    it "should support creating a new directory" do
      modifiable_share = 'modifiable'
      new_directory_name = 'my_new_directory'

      stdout = with_mocked_console(session) do |console|
        console.run_single("shares -i #{modifiable_share}")
        console.run_single("mkdir #{new_directory_name}")
      end

      ret = true
      ret &&= stdout.buf.include?("Directory #{new_directory_name} created")
      ret
    end

    it "should support deleting a directory" do
      modifiable_share = 'modifiable'
      new_directory_name = 'my_new_directory'

      stdout = with_mocked_console(session) do |console|
        console.run_single("shares -i #{modifiable_share}")
        console.run_single("rmdir #{new_directory_name}")
      end

      ret = true
      ret &&= stdout.buf.include?("Deleted #{new_directory_name}")
      ret
    end
  end

  def test_switching_shares
    it "should support switching shares" do
      stdout = with_mocked_console(session) { |console| console.run_single("shares -i 0") }
      ret = true
      ret &&= stdout.buf.include?('Successfully connected to modifiable')

      stdout = with_mocked_console(session) { |console| console.run_single("shares -i 1") }

      ret &&= stdout.buf.include?('Successfully connected to readonly')

      ret
    end
  end

  private

  def all_platforms
    Msf::Module::Platform.subclasses.collect { |c| c.realname.downcase }
  end

  # Wrap the console with a mocked stdin/stdout for testing purposes. This ensures the console
  # will not write the real stdout, and the contents can be verified in the test
  # @param [Session] session
  # @return [Rex::Ui::Text::Output::Buffer] the stdout buffer
  def with_mocked_console(session)
    old_input = session.console.input
    old_output = session.console.output

    mock_input = Rex::Ui::Text::Input.new
    mock_output = Rex::Ui::Text::Output::Buffer.new

    session.console.init_ui(mock_input, mock_output)
    yield session.console

    mock_output
  ensure
    session.console.init_ui(old_input, old_output)
  end
end
