#!/usr/bin/env ruby

require 'erb'

USAGE = "Usage: #{$0} <template> [<dir:$PWD>]"

class Build
  attr_reader :version
end

class CMake < Build
  def self.get_version(binary)
    `#{binary} --version`[/version ((?:\d+\.)*\d*)/, 1]
  end

  def initialize(binary = "cmake")
    @binary = binary
    @version = CMake.get_version @binary
  end
end

class Automake < Build
end

class Project
  attr_reader :name, :libname, :dirname, :sources, :scripts, :miscs, :language

  def initialize(name, libname, dirname, sources, scripts, miscs, language)
    @name = name
    @libname = libname
    @dirname = dirname
    @sources = sources
    @scripts = scripts
    @miscs = miscs
    @language = language
  end
end

class Generate
  attr_reader :project_boilerplate, :platform_boilerplate

  def initialize(project, platform)
    @project_boilerplate = project
    @platform_boilerplate = platform
  end
end

class Build
  def initialize(build_systems, project, generate)
    @cmake = build_systems[:cmake]
    @automake = build_systems[:automake]
    @project = project
    @generate = generate
  end

  def get_binding
    binding
  end
end

def template(t, b)
  erb = ERB.new(t, 0, "%")
  erb.result(b)
end

def die(msg)
  STDERR.puts("error: #{msg}")
  exit 1
end

def usage(code = 0)
  STDERR.puts USAGE
  exit code
end

def die_with_usage(msg)
  STDERR.puts("error: #{msg}")
  usage 1
end

def main
  if ARGV.include? '-h'
    usage
  end

  template_path = ARGV.shift
  die_with_usage("you must specify a template file") unless template_path

  unless File.file? template_path
    die("specified template file does not exist: #{template_path}")
  end

  project_dir = ARGV.shift
  project_dir ||= `pwd`.chomp
  project_dir = File.absolute_path(project_dir)

  unless File.directory? project_dir
    die("specified start directory does not exist: #{project_dir}")
  end

  project_name = File.basename project_dir
  project_dirname = File.basename File.dirname project_dir

  project_c_sources = Dir[File.join(project_dir, "*.c")].collect do |path|
    File.basename path
  end

  project_cxx_sources = Dir[File.join(project_dir, "*.cc")].collect do |path|
    File.basename path
  end

  project_header_sources = Dir[File.join(project_dir, "*.h")].collect do |path|
    File.basename path
  end

  project_sources = (project_c_sources + project_cxx_sources + project_header_sources).sort

  project_scripts = Dir[File.join(project_dir, "*.lua")].collect do |path|
    File.basename path
  end.sort

  project_miscs = Dir[File.join(project_dir, "*.txt")].collect do |path|
    File.basename path
  end.select do |name|
    !["CMakeLists.txt"].include?(name)
  end.sort

  if !project_cxx_sources.empty?
    project_language = "CXX"
  elsif !project_c_sources.empty?
    project_language = "C"
  else
    project_language = nil
  end

  cmake = CMake.new
  generate = Generate.new true, true
  project = Project.new project_name,
    project_name,
    project_dirname,
    project_sources,
    project_scripts,
    project_miscs,
    project_language

  build = Build.new({cmake: cmake}, project, generate)

  File.open(template_path) do |f|
    puts template f.read, build.get_binding
  end
end

main
