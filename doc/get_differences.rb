#!/usr/bin/ruby

# CONST REG_EX.  DO NOT CHANGE
delete_pattern = /add_deleted_comment\(\"(.*)\"\);/
diff_pattern = /add_diff_option_comment\(\"(.*)\",\s?\"(.*)\"\)/
template_diff = /<\s*&(.*),.*,\s*&(.*)>/
config_delete_template = /deleted_ctor<&(.*)>/
paths_diff = /paths_ctor<\s*&(.*)\s*>/  # check kws_paths.cc
normalizers_diff = /norm_sans_options_ctor<\s?&(.*)>/  # check pps_normalizers
unified2_diff = /unified2_ctor<\s?&(.*)>/  # checkout out_unified2.cc
star_reg = /\*/

if ARGV.empty?() || ARGV.length() > 1
    abort("Usage: ruby get_differences.rb <path_to_search>")
end

dir = ARGV[0];

if !File.directory?(dir)
    abort("Cannot find directory #{dir}")
end


arr = Array.new()

Dir.glob("#{dir}/**/*cc").each do |file|
    File.open(file) do |f|
        f.each_line do |line|
            if line =~ star_reg
                next
            end

            if line =~ delete_pattern
                arr << "deleted: #{$1}"
            end

            if line =~ diff_pattern
                arr << "change:  #{$1} ==> #{$2}"

            end

            if line =~ template_diff
                arr << "change:  #{$1}  ==> #{$2}"
            end

            if line =~ config_delete_template
                arr << "deleted: config #{$1}"
            end

            # Files with special templates

            if line =~ paths_diff
                arr << "change:  #{$1} ==> plugin_path"
            end
            
            if line =~ normalizers_diff
                arr << "change:  preprocessor normalize_#{$1} ==> #{$1} == <bool>"
            end

            if line =~ unified2_diff
                arr << "change:  #{$1} ==> unified2"
            end

        end
    end
end

arr.uniq!
arr.sort!

arr.each do |elem|
    puts "#{elem}"
end
